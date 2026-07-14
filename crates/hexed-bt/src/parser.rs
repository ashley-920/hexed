//! Recursive-descent parser for the `.bt` language, turning the lexer's token
//! stream into the [`ast`](crate::ast) types. Expressions use precedence
//! climbing; declarations vs. expression-statements are told apart with a small
//! lookahead heuristic (a type name is followed by an identifier).

use crate::ast::*;
use crate::lexer::{TokKind, Token};

#[derive(Clone, Debug, PartialEq)]
pub struct ParseError {
    pub msg: String,
    pub pos: usize,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "parse error at byte {}: {}", self.pos, self.msg)
    }
}

pub fn parse(tokens: &[Token]) -> Result<Program, ParseError> {
    let mut p = Parser { toks: tokens, pos: 0 };
    let mut items = Vec::new();
    while !p.at_eof() {
        items.push(p.parse_stmt()?);
    }
    Ok(items)
}

struct Parser<'a> {
    toks: &'a [Token],
    pos: usize,
}

fn bin_prec(op: &str) -> Option<u8> {
    Some(match op {
        "||" => 1,
        "&&" => 2,
        "|" => 3,
        "^" => 4,
        "&" => 5,
        "==" | "!=" => 6,
        "<" | ">" | "<=" | ">=" => 7,
        "<<" | ">>" => 8,
        "+" | "-" => 9,
        "*" | "/" | "%" => 10,
        _ => return None,
    })
}

const ASSIGN_OPS: &[&str] = &[
    "=", "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "<<=", ">>=",
];

impl<'a> Parser<'a> {
    // ---- token helpers ----
    fn kind_at(&self, off: usize) -> Option<&TokKind> {
        self.toks.get(self.pos + off).map(|t| &t.kind)
    }
    fn byte_pos(&self) -> usize {
        self.toks.get(self.pos).map(|t| t.start).unwrap_or(0)
    }
    fn at_eof(&self) -> bool {
        matches!(self.kind_at(0), Some(TokKind::Eof) | None)
    }
    fn err<T>(&self, msg: impl Into<String>) -> Result<T, ParseError> {
        Err(ParseError { msg: msg.into(), pos: self.byte_pos() })
    }
    fn at_punct(&self, p: &str) -> bool {
        matches!(self.kind_at(0), Some(TokKind::Punct(q)) if *q == p)
    }
    fn eat_punct(&mut self, p: &str) -> bool {
        if self.at_punct(p) {
            self.pos += 1;
            true
        } else {
            false
        }
    }
    fn expect_punct(&mut self, p: &str) -> Result<(), ParseError> {
        if self.eat_punct(p) {
            Ok(())
        } else {
            self.err(format!("expected `{p}`"))
        }
    }
    fn at_kw(&self, kw: &str) -> bool {
        matches!(self.kind_at(0), Some(TokKind::Ident(s)) if s == kw)
    }
    fn eat_kw(&mut self, kw: &str) -> bool {
        if self.at_kw(kw) {
            self.pos += 1;
            true
        } else {
            false
        }
    }
    fn expect_ident(&mut self) -> Result<String, ParseError> {
        if let Some(TokKind::Ident(s)) = self.kind_at(0) {
            let s = s.clone();
            self.pos += 1;
            Ok(s)
        } else {
            self.err("expected identifier")
        }
    }

    // ---- statements ----
    fn parse_stmt(&mut self) -> Result<Stmt, ParseError> {
        if self.at_kw("if") {
            return self.parse_if();
        }
        if self.at_kw("for") {
            return self.parse_for();
        }
        if self.at_kw("while") {
            return self.parse_while();
        }
        if self.at_kw("do") {
            return self.parse_do();
        }
        if self.eat_kw("return") {
            let e = if self.at_punct(";") { None } else { Some(self.parse_expr()?) };
            self.expect_punct(";")?;
            return Ok(Stmt::Return(e));
        }
        if self.eat_kw("break") {
            self.expect_punct(";")?;
            return Ok(Stmt::Break);
        }
        if self.eat_kw("continue") {
            self.expect_punct(";")?;
            return Ok(Stmt::Continue);
        }
        if self.at_punct("{") {
            return Ok(Stmt::Block(self.parse_block()?));
        }
        if self.eat_punct(";") {
            return Ok(Stmt::Empty);
        }
        if self.looks_like_decl() {
            return Ok(Stmt::Decl(self.parse_decl()?));
        }
        let e = self.parse_expr()?;
        self.expect_punct(";")?;
        Ok(Stmt::Expr(e))
    }

    fn looks_like_decl(&self) -> bool {
        if self.at_kw("struct") || self.at_kw("union") || self.at_kw("enum")
            || self.at_kw("typedef") || self.at_kw("local") || self.at_kw("const")
        {
            return true;
        }
        // `Type name` — an identifier immediately followed by another identifier.
        matches!(
            (self.kind_at(0), self.kind_at(1)),
            (Some(TokKind::Ident(_)), Some(TokKind::Ident(_)))
        )
    }

    fn parse_block(&mut self) -> Result<Vec<Stmt>, ParseError> {
        self.expect_punct("{")?;
        let mut stmts = Vec::new();
        while !self.at_punct("}") && !self.at_eof() {
            stmts.push(self.parse_stmt()?);
        }
        self.expect_punct("}")?;
        Ok(stmts)
    }

    fn parse_if(&mut self) -> Result<Stmt, ParseError> {
        self.eat_kw("if");
        self.expect_punct("(")?;
        let cond = self.parse_expr()?;
        self.expect_punct(")")?;
        let then_ = Box::new(self.parse_stmt()?);
        let else_ = if self.eat_kw("else") {
            Some(Box::new(self.parse_stmt()?))
        } else {
            None
        };
        Ok(Stmt::If { cond, then_, else_ })
    }

    fn parse_while(&mut self) -> Result<Stmt, ParseError> {
        self.eat_kw("while");
        self.expect_punct("(")?;
        let cond = self.parse_expr()?;
        self.expect_punct(")")?;
        let body = Box::new(self.parse_stmt()?);
        Ok(Stmt::While { cond, body })
    }

    fn parse_do(&mut self) -> Result<Stmt, ParseError> {
        self.eat_kw("do");
        let body = Box::new(self.parse_stmt()?);
        if !self.eat_kw("while") {
            return self.err("expected `while` after `do` body");
        }
        self.expect_punct("(")?;
        let cond = self.parse_expr()?;
        self.expect_punct(")")?;
        self.expect_punct(";")?;
        Ok(Stmt::DoWhile { body, cond })
    }

    fn parse_for(&mut self) -> Result<Stmt, ParseError> {
        self.eat_kw("for");
        self.expect_punct("(")?;
        let init = if self.at_punct(";") {
            self.pos += 1;
            None
        } else if self.looks_like_decl() {
            let d = self.parse_decl()?; // consumes trailing `;`
            Some(Box::new(Stmt::Decl(d)))
        } else {
            let e = self.parse_expr()?;
            self.expect_punct(";")?;
            Some(Box::new(Stmt::Expr(e)))
        };
        let cond = if self.at_punct(";") { None } else { Some(self.parse_expr()?) };
        self.expect_punct(";")?;
        let step = if self.at_punct(")") { None } else { Some(self.parse_expr()?) };
        self.expect_punct(")")?;
        let body = Box::new(self.parse_stmt()?);
        Ok(Stmt::For { init, cond, step, body })
    }

    // ---- declarations ----
    fn parse_decl(&mut self) -> Result<Decl, ParseError> {
        let is_typedef = self.eat_kw("typedef");
        self.eat_kw("const"); // ignore const qualifier
        let is_local = self.eat_kw("local");
        let ty = self.parse_type()?;

        // Bare struct/enum definition: `struct Foo { ... };`
        if !is_typedef && self.at_punct(";") {
            if let TypeRef::Struct(s) = &ty {
                if s.body.is_some() {
                    self.pos += 1;
                    return Ok(Decl::Struct((**s).clone()));
                }
            }
            if let TypeRef::Enum(e) = &ty {
                self.pos += 1;
                return Ok(Decl::Enum((**e).clone()));
            }
        }

        let name = self.expect_ident()?;

        // Function definition: `Type name(params) { body }`
        if self.at_punct("(") && !is_typedef {
            let params = self.parse_params()?;
            let body = self.parse_block()?;
            return Ok(Decl::Func(FuncDef { ret: ty, name, params, body }));
        }

        let array = self.parse_array_opt()?;
        let attrs = self.parse_attrs()?;
        let init = if self.eat_punct("=") { Some(self.parse_expr()?) } else { None };
        self.expect_punct(";")?;

        if is_typedef {
            Ok(Decl::Typedef { ty, name, array, attrs })
        } else {
            Ok(Decl::Var(VarDecl { ty, name, array, local: is_local, attrs, init }))
        }
    }

    fn parse_type(&mut self) -> Result<TypeRef, ParseError> {
        if self.eat_kw("struct") {
            return Ok(TypeRef::Struct(Box::new(self.parse_struct_rest(false)?)));
        }
        if self.eat_kw("union") {
            return Ok(TypeRef::Struct(Box::new(self.parse_struct_rest(true)?)));
        }
        if self.eat_kw("enum") {
            return Ok(TypeRef::Enum(Box::new(self.parse_enum_rest()?)));
        }
        Ok(TypeRef::Named(self.expect_ident()?))
    }

    fn parse_struct_rest(&mut self, is_union: bool) -> Result<StructDef, ParseError> {
        let name = if matches!(self.kind_at(0), Some(TokKind::Ident(_))) {
            Some(self.expect_ident()?)
        } else {
            None
        };
        // Ignore struct parameter lists: `struct Foo(args) { ... }`.
        if self.at_punct("(") {
            self.skip_paren_group()?;
        }
        let body = if self.at_punct("{") {
            Some(self.parse_block()?)
        } else {
            None
        };
        let attrs = self.parse_attrs()?;
        Ok(StructDef { is_union, name, body, attrs })
    }

    fn parse_enum_rest(&mut self) -> Result<EnumDef, ParseError> {
        let base = if self.eat_punct("<") {
            let b = self.expect_ident()?;
            self.expect_punct(">")?;
            Some(b)
        } else {
            None
        };
        let name = if matches!(self.kind_at(0), Some(TokKind::Ident(_))) {
            Some(self.expect_ident()?)
        } else {
            None
        };
        let mut variants = Vec::new();
        if self.eat_punct("{") {
            while !self.at_punct("}") && !self.at_eof() {
                let vname = self.expect_ident()?;
                let val = if self.eat_punct("=") { Some(self.parse_expr()?) } else { None };
                variants.push((vname, val));
                if !self.eat_punct(",") {
                    break;
                }
            }
            self.expect_punct("}")?;
        }
        let attrs = self.parse_attrs()?;
        Ok(EnumDef { name, base, variants, attrs })
    }

    fn parse_params(&mut self) -> Result<Vec<Param>, ParseError> {
        self.expect_punct("(")?;
        let mut params = Vec::new();
        while !self.at_punct(")") && !self.at_eof() {
            self.eat_kw("const");
            let ty = self.parse_type()?;
            let is_ref = self.eat_punct("&");
            let name = self.expect_ident()?;
            let array = self.parse_array_opt()?.is_some();
            params.push(Param { ty, name, is_ref, array });
            if !self.eat_punct(",") {
                break;
            }
        }
        self.expect_punct(")")?;
        Ok(params)
    }

    fn parse_array_opt(&mut self) -> Result<ArraySize, ParseError> {
        if self.eat_punct("[") {
            if self.eat_punct("]") {
                return Ok(Some(None));
            }
            let e = self.parse_expr()?;
            self.expect_punct("]")?;
            return Ok(Some(Some(e)));
        }
        Ok(None)
    }

    fn parse_attrs(&mut self) -> Result<Attrs, ParseError> {
        if !self.eat_punct("<") {
            return Ok(Attrs::default());
        }
        let mut list = Vec::new();
        while !self.at_punct(">") && !self.at_eof() {
            let key = self.expect_ident()?;
            // Attribute values are parsed without comparison ops so `>` closes
            // the list; arithmetic (prec >= 8) is still allowed.
            let val = if self.eat_punct("=") {
                Some(self.parse_binary(8)?)
            } else {
                None
            };
            list.push((key, val));
            if !self.eat_punct(",") {
                break;
            }
        }
        self.expect_punct(">")?;
        Ok(Attrs(list))
    }

    fn skip_paren_group(&mut self) -> Result<(), ParseError> {
        self.expect_punct("(")?;
        let mut depth = 1;
        while depth > 0 {
            if self.at_eof() {
                return self.err("unclosed `(`");
            }
            if self.at_punct("(") {
                depth += 1;
            } else if self.at_punct(")") {
                depth -= 1;
            }
            self.pos += 1;
        }
        Ok(())
    }

    // ---- expressions ----
    fn parse_expr(&mut self) -> Result<Expr, ParseError> {
        let lhs = self.parse_ternary()?;
        if let Some(TokKind::Punct(op)) = self.kind_at(0) {
            if ASSIGN_OPS.contains(op) {
                let op = *op;
                self.pos += 1;
                let value = self.parse_expr()?; // right assoc
                return Ok(Expr::Assign { op, target: Box::new(lhs), value: Box::new(value) });
            }
        }
        Ok(lhs)
    }

    fn parse_ternary(&mut self) -> Result<Expr, ParseError> {
        let cond = self.parse_binary(1)?;
        if self.eat_punct("?") {
            let then_ = self.parse_expr()?;
            self.expect_punct(":")?;
            let else_ = self.parse_ternary()?;
            return Ok(Expr::Ternary {
                cond: Box::new(cond),
                then_: Box::new(then_),
                else_: Box::new(else_),
            });
        }
        Ok(cond)
    }

    fn parse_binary(&mut self, min_prec: u8) -> Result<Expr, ParseError> {
        let mut lhs = self.parse_unary()?;
        while let Some(TokKind::Punct(op)) = self.kind_at(0) {
            let Some(prec) = bin_prec(op) else { break };
            if prec < min_prec {
                break;
            }
            let op = *op;
            self.pos += 1;
            let rhs = self.parse_binary(prec + 1)?; // left assoc
            lhs = Expr::Binary { op, lhs: Box::new(lhs), rhs: Box::new(rhs) };
        }
        Ok(lhs)
    }

    fn parse_unary(&mut self) -> Result<Expr, ParseError> {
        if let Some(TokKind::Punct(op)) = self.kind_at(0) {
            if matches!(*op, "!" | "~" | "-" | "+" | "++" | "--") {
                let op = *op;
                self.pos += 1;
                let expr = self.parse_unary()?;
                return Ok(Expr::Unary { op, prefix: true, expr: Box::new(expr) });
            }
        }
        if self.eat_kw("sizeof") {
            let e = if self.eat_punct("(") {
                let e = self.parse_expr()?;
                self.expect_punct(")")?;
                e
            } else {
                self.parse_unary()?
            };
            return Ok(Expr::Sizeof(Box::new(e)));
        }
        self.parse_postfix()
    }

    fn parse_postfix(&mut self) -> Result<Expr, ParseError> {
        let mut e = self.parse_primary()?;
        loop {
            if self.eat_punct("(") {
                let mut args = Vec::new();
                while !self.at_punct(")") && !self.at_eof() {
                    args.push(self.parse_expr()?);
                    if !self.eat_punct(",") {
                        break;
                    }
                }
                self.expect_punct(")")?;
                e = Expr::Call { callee: Box::new(e), args };
            } else if self.eat_punct("[") {
                let index = self.parse_expr()?;
                self.expect_punct("]")?;
                e = Expr::Index { base: Box::new(e), index: Box::new(index) };
            } else if self.eat_punct(".") {
                let name = self.expect_ident()?;
                e = Expr::Member { base: Box::new(e), name, arrow: false };
            } else if self.eat_punct("->") {
                let name = self.expect_ident()?;
                e = Expr::Member { base: Box::new(e), name, arrow: true };
            } else if self.at_punct("++") || self.at_punct("--") {
                let op = if self.at_punct("++") { "++" } else { "--" };
                self.pos += 1;
                e = Expr::Unary { op, prefix: false, expr: Box::new(e) };
            } else {
                break;
            }
        }
        Ok(e)
    }

    fn parse_primary(&mut self) -> Result<Expr, ParseError> {
        match self.kind_at(0).cloned() {
            Some(TokKind::Int(v)) => {
                self.pos += 1;
                Ok(Expr::Int(v))
            }
            Some(TokKind::Float(v)) => {
                self.pos += 1;
                Ok(Expr::Float(v))
            }
            Some(TokKind::Str(s)) => {
                self.pos += 1;
                Ok(Expr::Str(s))
            }
            Some(TokKind::Char(c)) => {
                self.pos += 1;
                Ok(Expr::Char(c))
            }
            Some(TokKind::Ident(name)) => {
                self.pos += 1;
                Ok(Expr::Ident(name))
            }
            Some(TokKind::Punct("(")) => {
                self.pos += 1;
                let e = self.parse_expr()?;
                self.expect_punct(")")?;
                Ok(e)
            }
            _ => self.err("expected an expression"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lexer::tokenize;

    fn parse_src(src: &str) -> Result<Program, ParseError> {
        parse(&tokenize(src).unwrap())
    }

    #[test]
    fn var_decls_and_arrays() {
        let p = parse_src("uint32 length; char type[4]; local int x = 3;").unwrap();
        assert_eq!(p.len(), 3);
        match &p[0] {
            Stmt::Decl(Decl::Var(v)) => {
                assert_eq!(v.ty, TypeRef::Named("uint32".into()));
                assert_eq!(v.name, "length");
                assert_eq!(v.array, None);
                assert!(!v.local);
            }
            other => panic!("{other:?}"),
        }
        match &p[1] {
            Stmt::Decl(Decl::Var(v)) => {
                assert_eq!(v.array, Some(Some(Expr::Int(4))));
            }
            other => panic!("{other:?}"),
        }
        match &p[2] {
            Stmt::Decl(Decl::Var(v)) => {
                assert!(v.local);
                assert_eq!(v.init, Some(Expr::Int(3)));
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn expression_precedence() {
        // 1 + 2 * 3 == 7  ->  (1 + (2*3)) == 7
        let p = parse_src("x = 1 + 2 * 3 == 7;").unwrap();
        let Stmt::Expr(Expr::Assign { value, .. }) = &p[0] else {
            panic!("{p:?}")
        };
        let Expr::Binary { op, lhs, .. } = value.as_ref() else {
            panic!("{value:?}")
        };
        assert_eq!(*op, "==");
        // lhs is 1 + (2*3)
        let Expr::Binary { op: add, rhs, .. } = lhs.as_ref() else {
            panic!()
        };
        assert_eq!(*add, "+");
        assert!(matches!(rhs.as_ref(), Expr::Binary { op: "*", .. }));
    }

    #[test]
    fn real_010_chunk_template() {
        let src = r#"
            typedef struct {
                uint32 length <format=decimal>;
                char   type[4];
                byte   data[length];
                uint32 crc <format=hex>;
            } CHUNK <bgcolor=cLtBlue>;

            while (!FEof())
                CHUNK chunk;
        "#;
        let p = parse_src(src).unwrap();
        assert_eq!(p.len(), 2);

        // The typedef of a struct with a body + attrs.
        match &p[0] {
            Stmt::Decl(Decl::Typedef { ty, name, attrs, .. }) => {
                assert_eq!(name, "CHUNK");
                assert_eq!(attrs.0[0].0, "bgcolor");
                let TypeRef::Struct(s) = ty else { panic!() };
                let body = s.body.as_ref().unwrap();
                assert_eq!(body.len(), 4);
                // first field has a <format=decimal> attribute
                match &body[0] {
                    Stmt::Decl(Decl::Var(v)) => {
                        assert_eq!(v.name, "length");
                        assert_eq!(v.attrs.0[0].0, "format");
                    }
                    other => panic!("{other:?}"),
                }
                // data[length] — array sized by a prior field
                match &body[2] {
                    Stmt::Decl(Decl::Var(v)) => {
                        assert_eq!(v.array, Some(Some(Expr::Ident("length".into()))));
                    }
                    other => panic!("{other:?}"),
                }
            }
            other => panic!("{other:?}"),
        }

        // while (!FEof()) CHUNK chunk;
        match &p[1] {
            Stmt::While { cond, body } => {
                assert!(matches!(cond, Expr::Unary { op: "!", .. }));
                assert!(matches!(body.as_ref(), Stmt::Decl(Decl::Var(_))));
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn enum_and_if_else() {
        let p = parse_src(
            "enum <uint16> Kind { A, B = 5, C }; if (x > 1) return 2; else break;",
        )
        .unwrap();
        match &p[0] {
            Stmt::Decl(Decl::Enum(e)) => {
                assert_eq!(e.base, Some("uint16".into()));
                assert_eq!(e.variants.len(), 3);
                assert_eq!(e.variants[1], ("B".into(), Some(Expr::Int(5))));
            }
            other => panic!("{other:?}"),
        }
        assert!(matches!(&p[1], Stmt::If { else_: Some(_), .. }));
    }

    #[test]
    fn function_def() {
        let p = parse_src("int add(int a, int b) { return a + b; }").unwrap();
        match &p[0] {
            Stmt::Decl(Decl::Func(f)) => {
                assert_eq!(f.name, "add");
                assert_eq!(f.params.len(), 2);
                assert_eq!(f.body.len(), 1);
            }
            other => panic!("{other:?}"),
        }
    }
}
