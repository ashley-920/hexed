//! Tree-walking interpreter for the `.bt` language.
//!
//! This is where a template actually *runs* against a byte buffer. The core
//! rule of 010's language: a **file-mapped** variable declaration (anything not
//! marked `local`) consumes bytes from the current file position as it is
//! executed, and produces a node in the results tree with its name, type,
//! offset, size, and decoded value. `local` variables are ordinary scratch
//! variables that don't touch the file.
//!
//! Everything else — structs, arrays, enums, typedefs, control flow, functions,
//! expressions — exists to drive those reads.

use crate::ast::*;
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Runtime values
// ---------------------------------------------------------------------------

/// A value produced while evaluating expressions or reading the file.
#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Void,
    Int(i64),
    Float(f64),
    Str(String),
    Array(Vec<Value>),
    /// A struct/union instance: field name → value (insertion order preserved).
    Struct(Vec<(String, Value)>),
}

impl Value {
    pub fn as_i64(&self) -> i64 {
        match self {
            Value::Int(v) => *v,
            Value::Float(v) => *v as i64,
            Value::Str(s) => s.len() as i64,
            _ => 0,
        }
    }
    pub fn as_f64(&self) -> f64 {
        match self {
            Value::Int(v) => *v as f64,
            Value::Float(v) => *v,
            _ => 0.0,
        }
    }
    pub fn truthy(&self) -> bool {
        match self {
            Value::Int(v) => *v != 0,
            Value::Float(v) => *v != 0.0,
            Value::Str(s) => !s.is_empty(),
            Value::Void => false,
            _ => true,
        }
    }
    fn field(&self, name: &str) -> Option<&Value> {
        match self {
            Value::Struct(fs) => fs.iter().find(|(k, _)| k == name).map(|(_, v)| v),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Output tree
// ---------------------------------------------------------------------------

/// One node in the parsed results tree (mirrors 010's template-results panel).
#[derive(Clone, Debug, PartialEq)]
pub struct Node {
    pub name: String,
    pub type_name: String,
    pub offset: usize,
    pub size: usize,
    /// Formatted for display (respecting `<format=...>` and enum names).
    pub display: String,
    /// `<bgcolor=...>` as 0xRRGGBB, if any.
    pub color: Option<u32>,
    pub children: Vec<Node>,
    pub is_array: bool,
}

/// The result of running a template.
#[derive(Clone, Debug, Default)]
pub struct Template {
    pub root: Vec<Node>,
    pub log: String,
    pub end_pos: usize,
}

#[derive(Clone, Debug, PartialEq)]
pub struct RunError {
    pub msg: String,
    pub pos: usize,
}

impl std::fmt::Display for RunError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "runtime error at offset {}: {}", self.pos, self.msg)
    }
}

/// Parse + run a template source string against `data`.
pub fn run(src: &str, data: &[u8]) -> Result<Template, String> {
    let toks = crate::lexer::tokenize(src).map_err(|e| e.to_string())?;
    let prog = crate::parser::parse(&toks).map_err(|e| e.to_string())?;
    interpret(&prog, data).map_err(|e| e.to_string())
}

/// Run an already-parsed program against `data`.
pub fn interpret(program: &Program, data: &[u8]) -> Result<Template, RunError> {
    let mut it = Interp::new(data);
    it.scopes.push(Scope::default());
    let mut root = Vec::new();
    it.exec_block_into(program, &mut root)?;
    Ok(Template { root, log: it.log, end_pos: it.pos })
}

// ---------------------------------------------------------------------------
// Interpreter state
// ---------------------------------------------------------------------------

#[derive(Default)]
struct Scope {
    vars: HashMap<String, Value>,
}

enum Flow {
    Normal,
    Break,
    Continue,
    Return(Value),
}

struct Interp<'a> {
    data: &'a [u8],
    pos: usize,
    little_endian: bool,
    scopes: Vec<Scope>,
    structs: HashMap<String, StructDef>,
    enums: HashMap<String, EnumDef>,
    /// typedef alias name → the type it resolves to.
    aliases: HashMap<String, TypeRef>,
    funcs: HashMap<String, FuncDef>,
    log: String,
    /// Loop-iteration budget — a template runs on the UI thread, so a
    /// non-advancing `while (!FEof())` must never hang the app.
    steps: u64,
    /// Current type-expansion recursion depth (structs within structs / arrays),
    /// bounded by [`MAX_TYPE_DEPTH`] so a self-referential struct can't overflow
    /// the stack (an uncatchable process abort).
    depth: u32,
}

/// Ceiling on total loop iterations across one run.
const STEP_BUDGET: u64 = 10_000_000;

/// Max nesting depth when expanding a type (struct/array) against the data. A
/// self-referential or mutually-recursive struct that consumes no bytes would
/// otherwise recurse until the thread stack aborts the process.
const MAX_TYPE_DEPTH: u32 = 256;

#[derive(Clone, Copy, PartialEq)]
enum Kind {
    Signed,
    Unsigned,
    Float,
    Char,
}

impl<'a> Interp<'a> {
    fn new(data: &'a [u8]) -> Self {
        Interp {
            data,
            pos: 0,
            little_endian: true,
            scopes: Vec::new(),
            structs: HashMap::new(),
            enums: HashMap::new(),
            aliases: HashMap::new(),
            funcs: HashMap::new(),
            log: String::new(),
            steps: 0,
            depth: 0,
        }
    }

    fn err<T>(&self, msg: impl Into<String>) -> Result<T, RunError> {
        Err(RunError { msg: msg.into(), pos: self.pos })
    }

    // ---- scope helpers ----
    fn lookup(&self, name: &str) -> Option<&Value> {
        for s in self.scopes.iter().rev() {
            if let Some(v) = s.vars.get(name) {
                return Some(v);
            }
        }
        None
    }
    fn bind(&mut self, name: &str, v: Value) {
        self.scopes.last_mut().unwrap().vars.insert(name.to_string(), v);
    }
    fn assign(&mut self, name: &str, v: Value) {
        for s in self.scopes.iter_mut().rev() {
            if s.vars.contains_key(name) {
                s.vars.insert(name.to_string(), v);
                return;
            }
        }
        // Implicit global if never declared.
        self.scopes.first_mut().unwrap().vars.insert(name.to_string(), v);
    }

    // ---- statement execution ----
    fn exec_block_into(&mut self, stmts: &[Stmt], out: &mut Vec<Node>) -> Result<Flow, RunError> {
        for st in stmts {
            match self.exec_stmt(st, out)? {
                Flow::Normal => {}
                other => return Ok(other),
            }
        }
        Ok(Flow::Normal)
    }

    fn exec_stmt(&mut self, st: &Stmt, out: &mut Vec<Node>) -> Result<Flow, RunError> {
        match st {
            Stmt::Empty => Ok(Flow::Normal),
            Stmt::Expr(e) => {
                self.eval(e)?;
                Ok(Flow::Normal)
            }
            Stmt::Block(b) => {
                self.scopes.push(Scope::default());
                let f = self.exec_block_into(b, out);
                self.scopes.pop();
                f
            }
            Stmt::Decl(d) => self.exec_decl(d, out),
            Stmt::If { cond, then_, else_ } => {
                if self.eval(cond)?.truthy() {
                    self.exec_stmt(then_, out)
                } else if let Some(e) = else_ {
                    self.exec_stmt(e, out)
                } else {
                    Ok(Flow::Normal)
                }
            }
            Stmt::While { cond, body } => {
                while self.eval(cond)?.truthy() {
                    match self.exec_stmt(body, out)? {
                        Flow::Break => break,
                        Flow::Return(v) => return Ok(Flow::Return(v)),
                        _ => {}
                    }
                    self.guard_progress()?;
                }
                Ok(Flow::Normal)
            }
            Stmt::DoWhile { body, cond } => {
                loop {
                    match self.exec_stmt(body, out)? {
                        Flow::Break => break,
                        Flow::Return(v) => return Ok(Flow::Return(v)),
                        _ => {}
                    }
                    self.guard_progress()?;
                    if !self.eval(cond)?.truthy() {
                        break;
                    }
                }
                Ok(Flow::Normal)
            }
            Stmt::For { init, cond, step, body } => {
                self.scopes.push(Scope::default());
                let res = (|| {
                    if let Some(i) = init {
                        self.exec_stmt(i, out)?;
                    }
                    loop {
                        if let Some(c) = cond {
                            if !self.eval(c)?.truthy() {
                                break;
                            }
                        }
                        match self.exec_stmt(body, out)? {
                            Flow::Break => break,
                            Flow::Return(v) => return Ok(Flow::Return(v)),
                            _ => {}
                        }
                        if let Some(s) = step {
                            self.eval(s)?;
                        }
                        self.guard_progress()?;
                    }
                    Ok(Flow::Normal)
                })();
                self.scopes.pop();
                res
            }
            Stmt::Return(e) => {
                let v = match e {
                    Some(e) => self.eval(e)?,
                    None => Value::Void,
                };
                Ok(Flow::Return(v))
            }
            Stmt::Break => Ok(Flow::Break),
            Stmt::Continue => Ok(Flow::Continue),
        }
    }

    /// Charge one loop iteration against the budget; bail on runaway loops.
    fn guard_progress(&mut self) -> Result<(), RunError> {
        self.steps += 1;
        if self.steps > STEP_BUDGET {
            return self.err("template exceeded loop budget (possible infinite loop)");
        }
        Ok(())
    }

    fn exec_decl(&mut self, d: &Decl, out: &mut Vec<Node>) -> Result<Flow, RunError> {
        match d {
            Decl::Struct(s) => {
                if let Some(n) = &s.name {
                    self.structs.insert(n.clone(), s.clone());
                }
                Ok(Flow::Normal)
            }
            Decl::Enum(e) => {
                if let Some(n) = &e.name {
                    self.enums.insert(n.clone(), e.clone());
                }
                Ok(Flow::Normal)
            }
            Decl::Func(f) => {
                self.funcs.insert(f.name.clone(), f.clone());
                Ok(Flow::Normal)
            }
            Decl::Typedef { ty, name, .. } => {
                self.register_type(ty);
                match ty {
                    TypeRef::Struct(s) => {
                        self.structs.insert(name.clone(), (**s).clone());
                    }
                    TypeRef::Enum(e) => {
                        self.enums.insert(name.clone(), (**e).clone());
                    }
                    TypeRef::Named(_) => {
                        self.aliases.insert(name.clone(), ty.clone());
                    }
                }
                Ok(Flow::Normal)
            }
            Decl::Var(v) => self.exec_var(v, out),
        }
    }

    /// Register any named type embedded in a type reference so later code can
    /// refer to it (e.g. `struct Foo {..} x;` also defines `Foo`).
    fn register_type(&mut self, ty: &TypeRef) {
        match ty {
            TypeRef::Struct(s) => {
                if let Some(n) = &s.name {
                    self.structs.insert(n.clone(), (**s).clone());
                }
            }
            TypeRef::Enum(e) => {
                if let Some(n) = &e.name {
                    self.enums.insert(n.clone(), (**e).clone());
                }
            }
            TypeRef::Named(_) => {}
        }
    }

    fn exec_var(&mut self, v: &VarDecl, out: &mut Vec<Node>) -> Result<Flow, RunError> {
        self.register_type(&v.ty);

        if v.local {
            // Scratch variable — evaluate initializer, no file read.
            let val = match &v.init {
                Some(e) => self.eval(e)?,
                None => Value::Int(0),
            };
            self.bind(&v.name, val);
            return Ok(Flow::Normal);
        }

        // File-mapped: consume bytes.
        match &v.array {
            None => {
                let (node, val) = self.read_type(&v.ty, &v.name, &v.attrs)?;
                self.bind(&v.name, val);
                out.push(node);
            }
            Some(size_expr) => {
                let count = match size_expr {
                    Some(e) => self.eval(e)?.as_i64().max(0) as usize,
                    None => 0,
                };
                let (node, val) = self.read_array(&v.ty, &v.name, count, &v.attrs)?;
                self.bind(&v.name, val);
                out.push(node);
            }
        }
        Ok(Flow::Normal)
    }

    // ---- type reading ----
    fn read_array(
        &mut self,
        ty: &TypeRef,
        name: &str,
        count: usize,
        attrs: &Attrs,
    ) -> Result<(Node, Value), RunError> {
        let start = self.pos;
        let color = self.color_of(attrs)?;

        // char/byte arrays render as a string.
        if let TypeRef::Named(tn) = ty {
            if let Some((sz, kind)) = builtin_type(&self.resolve_alias(tn)) {
                if sz == 1 && matches!(kind, Kind::Char | Kind::Signed | Kind::Unsigned) {
                    let end = self.pos + count;
                    if end > self.data.len() {
                        return self.err(format!("read past end of file reading {name}[{count}]"));
                    }
                    let raw = &self.data[self.pos..end];
                    self.pos = end;
                    let vals: Vec<Value> = raw.iter().map(|b| Value::Int(*b as i64)).collect();
                    let display = if kind == Kind::Char {
                        format!("\"{}\"", escape_str(raw))
                    } else {
                        format!("byte[{count}]  {}", hex_preview(raw))
                    };
                    let node = Node {
                        name: name.to_string(),
                        type_name: format!("{tn}[{count}]"),
                        offset: start,
                        size: count,
                        display,
                        color,
                        children: Vec::new(),
                        is_array: true,
                    };
                    return Ok((node, Value::Array(vals)));
                }
            }
        }

        // General array: read each element; expand struct/enum elements as
        // children, keep primitive elements collapsed.
        let mut children = Vec::new();
        let mut vals = Vec::new();
        let expand = !matches!(ty, TypeRef::Named(n) if builtin_type(&self.resolve_alias(n)).is_some());
        for i in 0..count {
            self.guard_progress()?; // charge each element against the loop budget
            let elem_start = self.pos;
            let elem_name = format!("{name}[{i}]");
            let (child, val) = self.read_type(ty, &elem_name, attrs)?;
            // A zero-width element (empty struct, or a struct whose fields all
            // sit at fixed positions) never advances the cursor, so a large
            // `count` would allocate `count` identical empty nodes and OOM/hang.
            // EOF can't stop it because nothing is read. Refuse it.
            if self.pos == elem_start && i >= 1 {
                return self.err(format!(
                    "array `{name}` element is zero-width; refusing to read {count} of them"
                ));
            }
            vals.push(val);
            if expand {
                children.push(child);
            }
        }
        let size = self.pos - start;
        let node = Node {
            name: name.to_string(),
            type_name: format!("{}[{count}]", type_name_of(ty)),
            offset: start,
            size,
            display: format!("{{ {count} elements }}"),
            color,
            children,
            is_array: true,
        };
        Ok((node, Value::Array(vals)))
    }

    fn read_type(
        &mut self,
        ty: &TypeRef,
        name: &str,
        attrs: &Attrs,
    ) -> Result<(Node, Value), RunError> {
        // Depth-guard every type expansion: a self-referential struct (e.g.
        // `struct A { A next; };`) that consumes no bytes would otherwise recurse
        // until the stack aborts the whole process.
        self.depth += 1;
        if self.depth > MAX_TYPE_DEPTH {
            self.depth -= 1;
            return self.err(format!("type `{name}` nested too deeply (recursive struct?)"));
        }
        let r = self.read_type_inner(ty, name, attrs);
        self.depth -= 1;
        r
    }

    fn read_type_inner(
        &mut self,
        ty: &TypeRef,
        name: &str,
        attrs: &Attrs,
    ) -> Result<(Node, Value), RunError> {
        match ty {
            TypeRef::Struct(s) => self.read_struct(s, name, attrs),
            TypeRef::Enum(e) => {
                let ed = (**e).clone();
                self.read_enum(&ed, name, attrs)
            }
            TypeRef::Named(tn) => {
                let resolved = self.resolve_alias(tn);
                if let Some((size, kind)) = builtin_type(&resolved) {
                    return self.read_primitive(&resolved, size, kind, name, attrs);
                }
                if let Some(sd) = self.structs.get(&resolved).cloned() {
                    return self.read_struct(&sd, name, attrs);
                }
                if let Some(ed) = self.enums.get(&resolved).cloned() {
                    return self.read_enum(&ed, name, attrs);
                }
                self.err(format!("unknown type `{tn}`"))
            }
        }
    }

    fn read_primitive(
        &mut self,
        type_name: &str,
        size: usize,
        kind: Kind,
        name: &str,
        attrs: &Attrs,
    ) -> Result<(Node, Value), RunError> {
        let start = self.pos;
        if self.pos + size > self.data.len() {
            return self.err(format!("read past end of file reading {type_name} {name}"));
        }
        let bytes = &self.data[self.pos..self.pos + size];
        self.pos += size;

        let val = decode_primitive(bytes, kind, self.little_endian);
        let display = self.format_value(&val, kind, attrs);
        let color = self.color_of(attrs)?;
        let node = Node {
            name: name.to_string(),
            type_name: type_name.to_string(),
            offset: start,
            size,
            display,
            color,
            children: Vec::new(),
            is_array: false,
        };
        Ok((node, val))
    }

    fn read_struct(
        &mut self,
        s: &StructDef,
        name: &str,
        attrs: &Attrs,
    ) -> Result<(Node, Value), RunError> {
        let start = self.pos;
        let Some(body) = &s.body else {
            return self.err(format!("struct `{name}` has no body to read"));
        };

        self.scopes.push(Scope::default());
        let mut children = Vec::new();
        let union_start = self.pos;
        let mut union_max = self.pos;

        let result = (|| {
            for st in body {
                if s.is_union {
                    self.pos = union_start; // each union member overlays the start
                }
                self.exec_stmt(st, &mut children)?;
                if s.is_union {
                    union_max = union_max.max(self.pos);
                }
            }
            Ok(())
        })();
        // Snapshot the struct's field bindings before popping its scope.
        let fields: Vec<(String, Value)> = self
            .scopes
            .last()
            .unwrap()
            .vars
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        self.scopes.pop();
        result?;

        if s.is_union {
            self.pos = union_max;
        }
        let size = self.pos - start;
        // Prefer struct-level attrs, falling back to the declaration's attrs.
        let color = if let Some(c) = self.color_of(&s.attrs)? {
            Some(c)
        } else {
            self.color_of(attrs)?
        };
        let node = Node {
            name: name.to_string(),
            type_name: s.name.clone().unwrap_or_else(|| "struct".into()),
            offset: start,
            size,
            display: format!("{{ {} fields }}", children.len()),
            color,
            children,
            is_array: false,
        };
        Ok((node, Value::Struct(fields)))
    }

    fn read_enum(
        &mut self,
        e: &EnumDef,
        name: &str,
        attrs: &Attrs,
    ) -> Result<(Node, Value), RunError> {
        let base = e.base.clone().unwrap_or_else(|| "int".into());
        let resolved = self.resolve_alias(&base);
        let (size, kind) = builtin_type(&resolved).unwrap_or((4, Kind::Signed));
        let start = self.pos;
        if self.pos + size > self.data.len() {
            return self.err(format!("read past end of file reading enum {name}"));
        }
        let bytes = &self.data[self.pos..self.pos + size];
        self.pos += size;
        let val = decode_primitive(bytes, kind, self.little_endian);
        let num = val.as_i64();

        // Match the numeric value to a variant name.
        let mut running = 0i64;
        let mut label = None;
        for (vname, ve) in &e.variants {
            if let Some(expr) = ve {
                running = self.eval(expr)?.as_i64();
            }
            if running == num {
                label = Some(vname.clone());
            }
            running += 1;
        }
        let display = match label {
            Some(l) => format!("{l} ({num})"),
            None => self.format_value(&val, kind, attrs),
        };
        let color = self.color_of(attrs)?;
        let node = Node {
            name: name.to_string(),
            type_name: e.name.clone().unwrap_or_else(|| "enum".into()),
            offset: start,
            size,
            display,
            color,
            children: Vec::new(),
            is_array: false,
        };
        Ok((node, val))
    }

    /// Follow typedef aliases down to a base type name.
    fn resolve_alias(&self, name: &str) -> String {
        let mut cur = name.to_string();
        let mut seen = 0;
        while let Some(TypeRef::Named(n)) = self.aliases.get(&cur) {
            cur = n.clone();
            seen += 1;
            if seen > 32 {
                break;
            }
        }
        cur
    }

    // ---- expression evaluation ----
    fn eval(&mut self, e: &Expr) -> Result<Value, RunError> {
        match e {
            Expr::Int(v) => Ok(Value::Int(*v)),
            Expr::Float(v) => Ok(Value::Float(*v)),
            Expr::Str(s) => Ok(Value::Str(s.clone())),
            Expr::Char(c) => Ok(Value::Int(*c as i64)),
            Expr::Ident(name) => {
                if let Some(v) = self.lookup(name) {
                    return Ok(v.clone());
                }
                // Bare enum constant?
                if let Some(v) = self.enum_constant(name)? {
                    return Ok(Value::Int(v));
                }
                self.err(format!("undefined identifier `{name}`"))
            }
            Expr::Unary { op, prefix, expr } => self.eval_unary(op, *prefix, expr),
            Expr::Binary { op, lhs, rhs } => self.eval_binary(op, lhs, rhs),
            Expr::Ternary { cond, then_, else_ } => {
                if self.eval(cond)?.truthy() {
                    self.eval(then_)
                } else {
                    self.eval(else_)
                }
            }
            Expr::Assign { op, target, value } => self.eval_assign(op, target, value),
            Expr::Call { callee, args } => self.eval_call(callee, args),
            Expr::Index { base, index } => {
                let b = self.eval(base)?;
                let i = self.eval(index)?.as_i64();
                match b {
                    Value::Array(items) => items
                        .get(i as usize)
                        .cloned()
                        .ok_or_else(|| RunError { msg: "index out of range".into(), pos: self.pos }),
                    Value::Str(s) => Ok(Value::Int(
                        s.as_bytes().get(i as usize).map(|b| *b as i64).unwrap_or(0),
                    )),
                    _ => self.err("cannot index non-array"),
                }
            }
            Expr::Member { base, name, .. } => {
                let b = self.eval(base)?;
                b.field(name)
                    .cloned()
                    .ok_or_else(|| RunError { msg: format!("no field `{name}`"), pos: self.pos })
            }
            Expr::Sizeof(inner) => {
                if let Expr::Ident(tn) = inner.as_ref() {
                    let resolved = self.resolve_alias(tn);
                    if let Some((sz, _)) = builtin_type(&resolved) {
                        return Ok(Value::Int(sz as i64));
                    }
                }
                let v = self.eval(inner)?;
                Ok(Value::Int(value_size_hint(&v) as i64))
            }
        }
    }

    fn enum_constant(&mut self, name: &str) -> Result<Option<i64>, RunError> {
        let enums: Vec<EnumDef> = self.enums.values().cloned().collect();
        for e in &enums {
            let mut running = 0i64;
            for (vname, ve) in &e.variants {
                if let Some(expr) = ve {
                    running = self.eval(expr)?.as_i64();
                }
                if vname == name {
                    return Ok(Some(running));
                }
                running += 1;
            }
        }
        Ok(None)
    }

    fn eval_unary(&mut self, op: &str, prefix: bool, expr: &Expr) -> Result<Value, RunError> {
        if matches!(op, "++" | "--") {
            // Only meaningful on an lvalue identifier.
            if let Expr::Ident(name) = expr {
                let old = self.lookup(name).cloned().unwrap_or(Value::Int(0)).as_i64();
                let new = if op == "++" { old.wrapping_add(1) } else { old.wrapping_sub(1) };
                self.assign(name, Value::Int(new));
                return Ok(Value::Int(if prefix { new } else { old }));
            }
            return self.eval(expr);
        }
        let v = self.eval(expr)?;
        Ok(match op {
            "!" => Value::Int(!v.truthy() as i64),
            "~" => Value::Int(!v.as_i64()),
            "-" => match v {
                Value::Float(f) => Value::Float(-f),
                // wrapping_neg: plain `-i64::MIN` overflow-panics.
                _ => Value::Int(v.as_i64().wrapping_neg()),
            },
            "+" => v,
            _ => v,
        })
    }

    fn eval_binary(&mut self, op: &str, lhs: &Expr, rhs: &Expr) -> Result<Value, RunError> {
        // Short-circuit logicals.
        if op == "&&" {
            return Ok(Value::Int(
                (self.eval(lhs)?.truthy() && self.eval(rhs)?.truthy()) as i64,
            ));
        }
        if op == "||" {
            return Ok(Value::Int(
                (self.eval(lhs)?.truthy() || self.eval(rhs)?.truthy()) as i64,
            ));
        }
        let l = self.eval(lhs)?;
        let r = self.eval(rhs)?;

        // String concatenation / comparison.
        if let (Value::Str(a), Value::Str(b)) = (&l, &r) {
            return Ok(match op {
                "+" => Value::Str(format!("{a}{b}")),
                "==" => Value::Int((a == b) as i64),
                "!=" => Value::Int((a != b) as i64),
                _ => Value::Int(0),
            });
        }

        let use_float = matches!(l, Value::Float(_)) || matches!(r, Value::Float(_));
        if use_float && matches!(op, "+" | "-" | "*" | "/") {
            let (a, b) = (l.as_f64(), r.as_f64());
            return Ok(Value::Float(match op {
                "+" => a + b,
                "-" => a - b,
                "*" => a * b,
                "/" => if b != 0.0 { a / b } else { 0.0 },
                _ => unreachable!(),
            }));
        }

        let (a, b) = (l.as_i64(), r.as_i64());
        Ok(Value::Int(match op {
            "+" => a.wrapping_add(b),
            "-" => a.wrapping_sub(b),
            "*" => a.wrapping_mul(b),
            "/" => if b != 0 { a.wrapping_div(b) } else { 0 },
            "%" => if b != 0 { a.wrapping_rem(b) } else { 0 },
            "&" => a & b,
            "|" => a | b,
            "^" => a ^ b,
            "<<" => a.wrapping_shl(b as u32),
            ">>" => a.wrapping_shr(b as u32),
            "==" => (compare(&l, &r) == std::cmp::Ordering::Equal) as i64,
            "!=" => (compare(&l, &r) != std::cmp::Ordering::Equal) as i64,
            "<" => (compare(&l, &r) == std::cmp::Ordering::Less) as i64,
            ">" => (compare(&l, &r) == std::cmp::Ordering::Greater) as i64,
            "<=" => (compare(&l, &r) != std::cmp::Ordering::Greater) as i64,
            ">=" => (compare(&l, &r) != std::cmp::Ordering::Less) as i64,
            _ => return self.err(format!("unknown operator `{op}`")),
        }))
    }

    fn eval_assign(&mut self, op: &str, target: &Expr, value: &Expr) -> Result<Value, RunError> {
        let Expr::Ident(name) = target else {
            // Assignment to array/member elements isn't tracked; evaluate RHS.
            return self.eval(value);
        };
        let rhs = self.eval(value)?;
        let new = if op == "=" {
            rhs
        } else {
            let cur = self.lookup(name).cloned().unwrap_or(Value::Int(0));
            let bin = &op[..op.len() - 1]; // strip '='
            let synth = Expr::Binary {
                op: intern_op(bin),
                lhs: Box::new(lit(&cur)),
                rhs: Box::new(lit(&rhs)),
            };
            self.eval(&synth)?
        };
        self.assign(name, new.clone());
        Ok(new)
    }

    fn eval_call(&mut self, callee: &Expr, args: &[Expr]) -> Result<Value, RunError> {
        let Expr::Ident(fname) = callee else {
            return self.err("cannot call non-function");
        };
        let mut argv = Vec::with_capacity(args.len());
        for a in args {
            argv.push(self.eval(a)?);
        }
        if let Some(v) = self.call_builtin(fname, &argv)? {
            return Ok(v);
        }
        if let Some(f) = self.funcs.get(fname).cloned() {
            return self.call_user(&f, argv);
        }
        self.err(format!("unknown function `{fname}`"))
    }

    fn call_user(&mut self, f: &FuncDef, argv: Vec<Value>) -> Result<Value, RunError> {
        self.scopes.push(Scope::default());
        for (p, v) in f.params.iter().zip(argv) {
            self.bind(&p.name, v);
        }
        let mut sink = Vec::new();
        let flow = self.exec_block_into(&f.body, &mut sink);
        self.scopes.pop();
        match flow? {
            Flow::Return(v) => Ok(v),
            _ => Ok(Value::Void),
        }
    }

    // ---- built-in functions ----
    fn call_builtin(&mut self, name: &str, args: &[Value]) -> Result<Option<Value>, RunError> {
        let a0 = || args.first().cloned().unwrap_or(Value::Int(0));
        let v = match name {
            "FTell" => Value::Int(self.pos as i64),
            "FEof" => Value::Int((self.pos >= self.data.len()) as i64),
            "FileSize" => Value::Int(self.data.len() as i64),
            "FSeek" => {
                self.pos = a0().as_i64().clamp(0, self.data.len() as i64) as usize;
                Value::Int(0)
            }
            "FSkip" => {
                let np = self.pos as i64 + a0().as_i64();
                self.pos = np.clamp(0, self.data.len() as i64) as usize;
                Value::Int(0)
            }
            "LittleEndian" => {
                self.little_endian = true;
                Value::Void
            }
            "BigEndian" => {
                self.little_endian = false;
                Value::Void
            }
            "IsLittleEndian" => Value::Int(self.little_endian as i64),
            "IsBigEndian" => Value::Int(!self.little_endian as i64),
            "ReadByte" | "ReadUByte" => self.peek_num(args, 1, Kind::Unsigned),
            "ReadShort" => self.peek_num(args, 2, Kind::Signed),
            "ReadUShort" => self.peek_num(args, 2, Kind::Unsigned),
            "ReadInt" | "ReadLong" => self.peek_num(args, 4, Kind::Signed),
            "ReadUInt" | "ReadULong" => self.peek_num(args, 4, Kind::Unsigned),
            "ReadInt64" | "ReadQuad" => self.peek_num(args, 8, Kind::Signed),
            "ReadUInt64" | "ReadUQuad" => self.peek_num(args, 8, Kind::Unsigned),
            "ReadFloat" => self.peek_num(args, 4, Kind::Float),
            "ReadDouble" => self.peek_num(args, 8, Kind::Float),
            "Strlen" => Value::Int(match a0() {
                Value::Str(s) => s.len() as i64,
                _ => 0,
            }),
            // ReadString(pos?, maxLen?) — NUL-terminated string, no advance.
            "ReadString" => {
                let at = args.first().map(|v| v.as_i64() as usize).unwrap_or(self.pos);
                let max = args.get(1).map(|v| v.as_i64() as usize).unwrap_or(usize::MAX);
                let mut s = String::new();
                let mut i = at;
                while i < self.data.len() && s.len() < max {
                    let b = self.data[i];
                    if b == 0 {
                        break;
                    }
                    s.push(b as char);
                    i += 1;
                }
                Value::Str(s)
            }
            // ArrayLength(arr) — element count of an array (or string length).
            "ArrayLength" => Value::Int(match args.first() {
                Some(Value::Array(a)) => a.len() as i64,
                Some(Value::Str(s)) => s.len() as i64,
                _ => 0,
            }),
            // Memcmp(pos1, pos2, len) — compare two file regions; 0 if equal.
            "Memcmp" => {
                let p1 = args.first().map(|v| v.as_i64() as usize).unwrap_or(0);
                let p2 = args.get(1).map(|v| v.as_i64() as usize).unwrap_or(0);
                let n = args.get(2).map(|v| v.as_i64() as usize).unwrap_or(0);
                // Cap to the data length: past EOF both sides read as 0, so
                // further iterations can never change the result — this stops a
                // hostile huge/negative length from hanging the UI thread, and
                // checked indexing stops a huge `p+k` from overflow-panicking.
                let n = n.min(self.data.len());
                let mut res = 0i64;
                for k in 0..n {
                    let x = p1.checked_add(k).and_then(|i| self.data.get(i)).copied().unwrap_or(0);
                    let y = p2.checked_add(k).and_then(|i| self.data.get(i)).copied().unwrap_or(0);
                    if x != y {
                        res = x as i64 - y as i64;
                        break;
                    }
                }
                Value::Int(res)
            }
            // Strcmp(a, b) — string compare, C-style sign.
            "Strcmp" => {
                let sa = if let Some(Value::Str(s)) = args.first() { s.as_str() } else { "" };
                let sb = if let Some(Value::Str(s)) = args.get(1) { s.as_str() } else { "" };
                Value::Int(match sa.cmp(sb) {
                    std::cmp::Ordering::Less => -1,
                    std::cmp::Ordering::Equal => 0,
                    std::cmp::Ordering::Greater => 1,
                })
            }
            "Printf" | "Warning" | "Print" => {
                let s = self.printf(args);
                self.log.push_str(&s);
                Value::Void
            }
            "Abs" => Value::Int(a0().as_i64().saturating_abs()),
            "Min" => Value::Int(
                args.iter().map(|v| v.as_i64()).min().unwrap_or(0),
            ),
            "Max" => Value::Int(
                args.iter().map(|v| v.as_i64()).max().unwrap_or(0),
            ),
            _ => return Ok(None),
        };
        Ok(Some(v))
    }

    /// Peek a numeric value without advancing the cursor. Optional first arg is
    /// an absolute position (defaults to the current cursor).
    fn peek_num(&self, args: &[Value], size: usize, kind: Kind) -> Value {
        // A negative position argument casts to a huge usize; use checked math
        // so it (and any out-of-range position) returns 0 instead of overflow-
        // panicking on `at + size` or OOB-slicing `self.data[at..]`.
        let at = args.first().map(|v| v.as_i64() as usize).unwrap_or(self.pos);
        let end = match at.checked_add(size) {
            Some(e) if e <= self.data.len() => e,
            _ => return Value::Int(0),
        };
        decode_primitive(&self.data[at..end], kind, self.little_endian)
    }

    fn printf(&mut self, args: &[Value]) -> String {
        let Some(Value::Str(fmt)) = args.first() else {
            return String::new();
        };
        let mut out = String::new();
        let mut ai = 1;
        let mut chars = fmt.chars().peekable();
        while let Some(c) = chars.next() {
            if c != '%' {
                out.push(c);
                continue;
            }
            // Collect a minimal format spec: flags/width then a conversion.
            let mut spec = String::from("%");
            while let Some(&n) = chars.peek() {
                spec.push(n);
                chars.next();
                if n.is_ascii_alphabetic() || n == '%' {
                    break;
                }
            }
            let conv = spec.chars().last().unwrap_or('%');
            let arg = args.get(ai).cloned().unwrap_or(Value::Void);
            match conv {
                '%' => out.push('%'),
                'd' | 'i' | 'u' | 'l' | 'L' => {
                    out.push_str(&arg.as_i64().to_string());
                    ai += 1;
                }
                'x' => {
                    out.push_str(&fmt_hex(&spec, arg.as_i64(), false));
                    ai += 1;
                }
                'X' => {
                    out.push_str(&fmt_hex(&spec, arg.as_i64(), true));
                    ai += 1;
                }
                'c' => {
                    out.push(char::from_u32(arg.as_i64() as u32).unwrap_or('?'));
                    ai += 1;
                }
                'f' | 'g' | 'e' => {
                    out.push_str(&arg.as_f64().to_string());
                    ai += 1;
                }
                's' => {
                    if let Value::Str(s) = &arg {
                        out.push_str(s);
                    } else {
                        out.push_str(&arg.as_i64().to_string());
                    }
                    ai += 1;
                }
                _ => out.push_str(&spec),
            }
        }
        out
    }

    // ---- formatting / attributes ----
    fn format_value(&self, v: &Value, kind: Kind, attrs: &Attrs) -> String {
        let fmt = attrs.get("format").and_then(|o| o.as_ref());
        if let Some(Expr::Ident(f)) = fmt {
            let n = v.as_i64();
            match f.as_str() {
                "hex" => return format!("0x{:X}", n),
                "binary" => return format!("0b{:b}", n),
                "octal" => return format!("0o{:o}", n),
                "decimal" => {
                    return if kind == Kind::Unsigned {
                        (n as u64).to_string()
                    } else {
                        n.to_string()
                    }
                }
                _ => {}
            }
        }
        match kind {
            Kind::Float => v.as_f64().to_string(),
            Kind::Char => {
                let n = v.as_i64();
                let c = n as u8 as char;
                if c.is_ascii_graphic() || c == ' ' {
                    format!("{n} '{c}'")
                } else {
                    n.to_string()
                }
            }
            // Values are decoded into an i64; an unsigned field above i64::MAX
            // is stored with the sign bit set, so render it back through u64 or
            // it prints as a spurious negative.
            Kind::Unsigned => (v.as_i64() as u64).to_string(),
            _ => v.as_i64().to_string(),
        }
    }

    fn color_of(&mut self, attrs: &Attrs) -> Result<Option<u32>, RunError> {
        let Some(val) = attrs.get("bgcolor").or_else(|| attrs.get("color")) else {
            return Ok(None);
        };
        match val {
            Some(Expr::Ident(name)) => Ok(named_color(name)),
            Some(e) => {
                let n = self.eval(e)?.as_i64() as u32;
                // 010 stores colors as 0xBBGGRR; convert to 0xRRGGBB.
                let (b, g, r) = ((n >> 16) & 0xFF, (n >> 8) & 0xFF, n & 0xFF);
                Ok(Some((r << 16) | (g << 8) | b))
            }
            None => Ok(None),
        }
    }
}

// ---------------------------------------------------------------------------
// Free helpers
// ---------------------------------------------------------------------------

/// Map a 010 built-in type name to (byte size, kind). Returns `None` for
/// non-primitive (struct/enum/typedef) names.
fn builtin_type(name: &str) -> Option<(usize, Kind)> {
    Some(match name {
        // 1 byte
        "char" | "byte" | "int8" | "CHAR" => (1, Kind::Char),
        "uchar" | "ubyte" | "uint8" | "UCHAR" | "UBYTE" | "BYTE" => (1, Kind::Unsigned),
        // 2 bytes
        "short" | "int16" | "SHORT" => (2, Kind::Signed),
        "ushort" | "uint16" | "USHORT" | "WORD" | "WCHAR" => (2, Kind::Unsigned),
        // 4 bytes
        "int" | "int32" | "long" | "INT" | "LONG" | "int32_t" => (4, Kind::Signed),
        "uint" | "uint32" | "ulong" | "UINT" | "ULONG" | "DWORD" | "uint32_t" => {
            (4, Kind::Unsigned)
        }
        // 8 bytes
        "int64" | "quad" | "QUAD" | "__int64" | "INT64" | "int64_t" => (8, Kind::Signed),
        "uint64" | "uquad" | "UQUAD" | "QWORD" | "UINT64" | "uint64_t" => (8, Kind::Unsigned),
        // floats
        "float" | "FLOAT" => (4, Kind::Float),
        "double" | "DOUBLE" => (8, Kind::Float),
        _ => return None,
    })
}

fn decode_primitive(bytes: &[u8], kind: Kind, le: bool) -> Value {
    let mut buf = [0u8; 8];
    let n = bytes.len().min(8);
    buf[..n].copy_from_slice(&bytes[..n]);
    let raw = if le {
        u64::from_le_bytes(buf)
    } else {
        // Big-endian: the bytes occupy the high end.
        let mut b = [0u8; 8];
        b[8 - n..].copy_from_slice(&bytes[..n]);
        u64::from_be_bytes(b)
    };
    match kind {
        Kind::Float => {
            if bytes.len() == 4 {
                Value::Float(f32::from_bits(raw as u32) as f64)
            } else {
                Value::Float(f64::from_bits(raw))
            }
        }
        Kind::Unsigned | Kind::Char => Value::Int(raw as i64),
        Kind::Signed => {
            let bits = (n * 8) as u32;
            let shifted = (raw << (64 - bits)) as i64 >> (64 - bits);
            Value::Int(shifted)
        }
    }
}

fn compare(a: &Value, b: &Value) -> std::cmp::Ordering {
    if matches!(a, Value::Float(_)) || matches!(b, Value::Float(_)) {
        a.as_f64().partial_cmp(&b.as_f64()).unwrap_or(std::cmp::Ordering::Equal)
    } else {
        a.as_i64().cmp(&b.as_i64())
    }
}

fn value_size_hint(v: &Value) -> usize {
    match v {
        Value::Float(_) => 8,
        Value::Array(items) => items.iter().map(value_size_hint).sum(),
        Value::Str(s) => s.len(),
        _ => 4,
    }
}

fn type_name_of(ty: &TypeRef) -> String {
    match ty {
        TypeRef::Named(n) => n.clone(),
        TypeRef::Struct(s) => s.name.clone().unwrap_or_else(|| "struct".into()),
        TypeRef::Enum(e) => e.name.clone().unwrap_or_else(|| "enum".into()),
    }
}

fn lit(v: &Value) -> Expr {
    match v {
        Value::Float(f) => Expr::Float(*f),
        Value::Str(s) => Expr::Str(s.clone()),
        _ => Expr::Int(v.as_i64()),
    }
}

fn intern_op(op: &str) -> &'static str {
    match op {
        "+" => "+",
        "-" => "-",
        "*" => "*",
        "/" => "/",
        "%" => "%",
        "&" => "&",
        "|" => "|",
        "^" => "^",
        "<<" => "<<",
        ">>" => ">>",
        _ => "+",
    }
}

fn escape_str(raw: &[u8]) -> String {
    let mut s = String::new();
    for &b in raw {
        let c = b as char;
        if c == '\0' {
            break;
        }
        if c.is_ascii_graphic() || c == ' ' {
            s.push(c);
        } else {
            s.push('.');
        }
    }
    s
}

fn hex_preview(raw: &[u8]) -> String {
    let mut s = String::new();
    for (i, b) in raw.iter().take(16).enumerate() {
        if i > 0 {
            s.push(' ');
        }
        s.push_str(&format!("{b:02X}"));
    }
    if raw.len() > 16 {
        s.push_str(" …");
    }
    s
}

fn fmt_hex(spec: &str, val: i64, upper: bool) -> String {
    // Parse a `%0Nx`-style width/zero-pad out of the spec.
    let inner = &spec[1..spec.len().saturating_sub(1)];
    let zero = inner.starts_with('0');
    let width: usize = inner.trim_start_matches('0').parse().unwrap_or(0);
    let base = if upper {
        format!("{:X}", val)
    } else {
        format!("{:x}", val)
    };
    if base.len() >= width {
        base
    } else if zero {
        format!("{}{}", "0".repeat(width - base.len()), base)
    } else {
        format!("{}{}", " ".repeat(width - base.len()), base)
    }
}

/// A handful of 010's named color constants, as 0xRRGGBB.
fn named_color(name: &str) -> Option<u32> {
    Some(match name {
        "cRed" => 0xFF0000,
        "cLtRed" => 0xFF8080,
        "cDkRed" => 0x800000,
        "cGreen" => 0x00FF00,
        "cLtGreen" => 0x80FF80,
        "cDkGreen" => 0x008000,
        "cBlue" => 0x0000FF,
        "cLtBlue" => 0x8080FF,
        "cDkBlue" => 0x000080,
        "cPurple" => 0xFF00FF,
        "cLtPurple" => 0xFF80FF,
        "cAqua" => 0x00FFFF,
        "cLtAqua" => 0x80FFFF,
        "cYellow" => 0xFFFF00,
        "cLtYellow" => 0xFFFF80,
        "cGray" | "cGrey" => 0x808080,
        "cLtGray" | "cLtGrey" => 0xC0C0C0,
        "cDkGray" | "cDkGrey" => 0x404040,
        "cWhite" => 0xFFFFFF,
        "cBlack" => 0x000000,
        "cNone" => return None,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run_ok(src: &str, data: &[u8]) -> Template {
        run(src, data).unwrap()
    }

    #[test]
    fn reads_primitives_little_endian() {
        // uint32 = 0x04030201, then a byte.
        let data = [0x01, 0x02, 0x03, 0x04, 0xFF];
        let t = run_ok("uint32 magic; ubyte flag;", &data);
        assert_eq!(t.root.len(), 2);
        assert_eq!(t.root[0].name, "magic");
        assert_eq!(t.root[0].offset, 0);
        assert_eq!(t.root[0].size, 4);
        assert_eq!(t.root[0].display, "67305985"); // 0x04030201
        assert_eq!(t.root[1].display, "255");
        assert_eq!(t.end_pos, 5);
    }

    #[test]
    fn big_endian_and_format_hex() {
        let data = [0x01, 0x02, 0x03, 0x04];
        let t = run_ok("BigEndian(); uint32 v <format=hex>;", &data);
        assert_eq!(t.root[0].display, "0x1020304");
    }

    #[test]
    fn char_array_is_string() {
        let data = b"PNG\x00rest";
        let t = run_ok("char sig[3];", data);
        assert_eq!(t.root[0].display, "\"PNG\"");
        assert_eq!(t.root[0].size, 3);
    }

    #[test]
    fn struct_with_field_sized_array() {
        // length=3, then 3 data bytes.
        let data = [0x03, 0x00, 0x00, 0x00, 0xAA, 0xBB, 0xCC];
        let src = r#"
            struct Blob {
                uint32 length;
                ubyte  data[length];
            } blob;
        "#;
        let t = run_ok(src, &data);
        assert_eq!(t.root.len(), 1);
        let blob = &t.root[0];
        assert_eq!(blob.children.len(), 2);
        assert_eq!(blob.children[0].name, "length");
        assert_eq!(blob.children[1].size, 3);
        assert_eq!(t.end_pos, 7);
    }

    #[test]
    fn enum_maps_value_to_name() {
        let data = [0x02, 0x00, 0x00, 0x00];
        let src = "enum <uint32> Color { Red, Green, Blue } c;";
        let t = run_ok(src, &data);
        assert!(t.root[0].display.starts_with("Blue"));
    }

    #[test]
    fn while_loop_over_png_chunks() {
        // Two minimal "chunks": [len=1][type=4][data=len][crc=4]
        let mut data = Vec::new();
        for tag in [b"IHDR", b"IDAT"] {
            data.extend_from_slice(&1u32.to_le_bytes()); // length = 1
            data.extend_from_slice(tag); // 4-byte type
            data.push(0x77); // 1 data byte
            data.extend_from_slice(&0xDEADBEEFu32.to_le_bytes()); // crc
        }
        let src = r#"
            typedef struct {
                uint32 length;
                char   type[4];
                ubyte  data[length];
                uint32 crc <format=hex>;
            } CHUNK;

            while (!FEof())
                CHUNK chunk;
        "#;
        let t = run_ok(src, &data);
        assert_eq!(t.root.len(), 2);
        assert_eq!(t.root[0].children[1].display, "\"IHDR\"");
        assert_eq!(t.root[1].children[1].display, "\"IDAT\"");
        assert_eq!(t.end_pos, data.len());
    }

    #[test]
    fn shipped_png_template_with_braced_loop() {
        // Mirrors app/templates/png.bt exactly (leading signature + braced
        // while body) to guard the bundled template against parser drift.
        let src = r#"
            BigEndian();
            char signature[8] <bgcolor=cLtGreen>;
            typedef struct {
                uint32 length;
                char   ctype[4];
                ubyte  data[length];
                uint32 crc <format=hex>;
            } CHUNK <bgcolor=cLtBlue>;
            while (!FEof()) {
                CHUNK chunk;
            }
        "#;
        let mut data = Vec::new();
        data.extend_from_slice(&[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]);
        // IHDR: length=2 (big-endian), type, 2 data bytes, crc
        data.extend_from_slice(&2u32.to_be_bytes());
        data.extend_from_slice(b"IHDR");
        data.extend_from_slice(&[0x11, 0x22]);
        data.extend_from_slice(&0xAABBCCDDu32.to_be_bytes());
        // IEND: length=0
        data.extend_from_slice(&0u32.to_be_bytes());
        data.extend_from_slice(b"IEND");
        data.extend_from_slice(&0xAE426082u32.to_be_bytes());

        let t = run_ok(src, &data);
        assert_eq!(t.root.len(), 3); // signature + 2 chunks
        assert_eq!(t.root[0].name, "signature");
        assert!(t.root[0].color.is_some());
        assert_eq!(t.root[1].children[1].display, "\"IHDR\"");
        assert_eq!(t.root[2].children[1].display, "\"IEND\"");
        assert_eq!(t.end_pos, data.len());
    }

    #[test]
    fn local_vars_and_functions() {
        let data = [10u8, 20, 30, 40];
        let src = r#"
            int sum(int a, int b) { return a + b; }
            local int total = 0;
            ubyte a;
            ubyte b;
            total = sum(a, b);
            Printf("total=%d", total);
        "#;
        let t = run_ok(src, &data);
        // Only the two file-mapped bytes appear in the tree.
        assert_eq!(t.root.len(), 2);
        assert_eq!(t.log, "total=30");
    }

    #[test]
    fn if_else_and_expressions() {
        let data = [0x05];
        let src = r#"
            ubyte n;
            local int x = (n > 3) ? n * 2 : 0;
            Printf("%d", x);
        "#;
        let t = run_ok(src, &data);
        assert_eq!(t.log, "10");
    }

    #[test]
    fn builtin_read_string_and_length() {
        // "HI\0" then a uint32 = 5, then a 5-element array.
        let mut data = vec![b'H', b'I', 0];
        data.extend_from_slice(&5u32.to_le_bytes());
        data.extend_from_slice(&[1, 2, 3, 4, 5]);
        let src = r#"
            local string name = ReadString(0);
            FSkip(3);                 // ReadString is a peek; consume "HI\0"
            uint32 count;
            ubyte items[count];
            Printf("name=%s len=%d items=%d", name, Strlen(name), ArrayLength(items));
        "#;
        let t = run_ok(src, &data);
        assert_eq!(t.log, "name=HI len=2 items=5");
    }

    #[test]
    fn elf_template_conditional_layout() {
        // Mirrors app/templates/elf.bt: member access, conditional endianness,
        // and if/else branching that reads different widths.
        let src = r#"
            LittleEndian();
            struct {
                char  magic[4];
                ubyte ei_class;
                ubyte ei_data;
                ubyte ei_version;
                ubyte ei_osabi;
                ubyte ei_abiversion;
                ubyte ei_pad[7];
            } e_ident;
            if (e_ident.ei_data == 2)
                BigEndian();
            local int is64 = (e_ident.ei_class == 2);
            uint16 e_type;
            uint16 e_machine;
            uint32 e_version;
            if (is64) {
                uint64 e_entry;
                uint64 e_phoff;
                uint64 e_shoff;
            } else {
                uint32 e_entry;
                uint32 e_phoff;
                uint32 e_shoff;
            }
        "#;
        // magic[4] + class,data,version,osabi,abiversion (5) then pad[7].
        let mut data = vec![0x7F, b'E', b'L', b'F', 2, 1, 1, 0, 0];
        data.extend_from_slice(&[0u8; 7]); // ei_pad
        data.extend_from_slice(&2u16.to_le_bytes()); // e_type
        data.extend_from_slice(&0x3Eu16.to_le_bytes()); // e_machine = x86-64
        data.extend_from_slice(&1u32.to_le_bytes()); // e_version
        data.extend_from_slice(&0x401000u64.to_le_bytes()); // e_entry
        data.extend_from_slice(&64u64.to_le_bytes()); // e_phoff
        data.extend_from_slice(&0u64.to_le_bytes()); // e_shoff
        let t = run_ok(src, &data);
        // e_ident, e_type, e_machine, e_version, e_entry, e_phoff, e_shoff
        assert_eq!(t.root.len(), 7);
        assert_eq!(t.root[2].name, "e_machine");
        assert_eq!(t.root[2].display, "62");
        assert_eq!(t.root[4].name, "e_entry");
        assert_eq!(t.root[4].size, 8); // 64-bit branch taken
        assert_eq!(t.end_pos, data.len());
    }

    #[test]
    fn builtin_memcmp() {
        let data = *b"MZMZxxxx";
        let src = r#"
            Printf("%d,", Memcmp(0, 2, 2));  // "MZ" vs "MZ" -> 0
            Printf("%d", Memcmp(0, 4, 2));   // "MZ" vs "xx" -> nonzero
        "#;
        let t = run_ok(src, &data);
        assert!(t.log.starts_with("0,"));
        assert_ne!(t.log, "0,0");
    }

    #[test]
    fn read_past_end_errors() {
        let data = [0x01, 0x02];
        let e = run("uint32 big;", &data).unwrap_err();
        assert!(e.contains("past end"));
    }
}
