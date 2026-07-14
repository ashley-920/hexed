//! AST for the `.bt` template language.

#[derive(Clone, Debug, PartialEq)]
pub enum Expr {
    Int(i64),
    Float(f64),
    Str(String),
    Char(char),
    Ident(String),
    /// Prefix (`!x`, `-x`, `++x`) or postfix (`x++`) unary op.
    Unary { op: &'static str, prefix: bool, expr: Box<Expr> },
    Binary { op: &'static str, lhs: Box<Expr>, rhs: Box<Expr> },
    Ternary { cond: Box<Expr>, then_: Box<Expr>, else_: Box<Expr> },
    Assign { op: &'static str, target: Box<Expr>, value: Box<Expr> },
    Call { callee: Box<Expr>, args: Vec<Expr> },
    Index { base: Box<Expr>, index: Box<Expr> },
    Member { base: Box<Expr>, name: String, arrow: bool },
    Sizeof(Box<Expr>),
}

/// `<key=value, key2, ...>` annotations on a declaration.
#[derive(Clone, Debug, PartialEq, Default)]
pub struct Attrs(pub Vec<(String, Option<Expr>)>);

impl Attrs {
    pub fn get(&self, key: &str) -> Option<&Option<Expr>> {
        self.0.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum TypeRef {
    Named(String),
    Struct(Box<StructDef>),
    Enum(Box<EnumDef>),
}

#[derive(Clone, Debug, PartialEq)]
pub struct StructDef {
    pub is_union: bool,
    pub name: Option<String>,
    /// `Some` when a body `{ ... }` was present (a definition); `None` for a
    /// bare reference like `struct Foo var;`.
    pub body: Option<Vec<Stmt>>,
    pub attrs: Attrs,
}

#[derive(Clone, Debug, PartialEq)]
pub struct EnumDef {
    pub name: Option<String>,
    pub base: Option<String>,
    pub variants: Vec<(String, Option<Expr>)>,
    pub attrs: Attrs,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Param {
    pub ty: TypeRef,
    pub name: String,
    pub is_ref: bool,
    pub array: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct FuncDef {
    pub ret: TypeRef,
    pub name: String,
    pub params: Vec<Param>,
    pub body: Vec<Stmt>,
}

/// `None` = not an array; `Some(None)` = `[]`; `Some(Some(e))` = `[e]`.
pub type ArraySize = Option<Option<Expr>>;

#[derive(Clone, Debug, PartialEq)]
pub struct VarDecl {
    pub ty: TypeRef,
    pub name: String,
    pub array: ArraySize,
    /// `local` — not file-mapped (doesn't consume bytes).
    pub local: bool,
    pub attrs: Attrs,
    pub init: Option<Expr>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Decl {
    Var(VarDecl),
    Struct(StructDef),
    Enum(EnumDef),
    Typedef { ty: TypeRef, name: String, array: ArraySize, attrs: Attrs },
    Func(FuncDef),
}

#[derive(Clone, Debug, PartialEq)]
pub enum Stmt {
    Expr(Expr),
    Decl(Decl),
    Block(Vec<Stmt>),
    If { cond: Expr, then_: Box<Stmt>, else_: Option<Box<Stmt>> },
    For { init: Option<Box<Stmt>>, cond: Option<Expr>, step: Option<Expr>, body: Box<Stmt> },
    While { cond: Expr, body: Box<Stmt> },
    DoWhile { body: Box<Stmt>, cond: Expr },
    Return(Option<Expr>),
    Break,
    Continue,
    Empty,
}

pub type Program = Vec<Stmt>;
