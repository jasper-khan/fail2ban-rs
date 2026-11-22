//! Fail2Ban 1.1.1 `Observer` ban-time escalation and expression evaluator (`bantime.*`).
//!
//! Mirrors `Jail.setBanTimeExtra` / `Jail.getMaxBanTime` in `fail2ban/server/jail.py`
//! and `ObserverThread.calcBanTime` / `incrBanTime` / `failureFound` in `fail2ban/server/observer.py`.

use std::fs::File;
use std::io::Read;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::db::Fail2BanDb;
use crate::duration::{parse_bool, str2seconds_i64};
use crate::error::{Error, Result};
use crate::protocol::PickleValue;
use crate::ticket::Ticket;

/// Default exponential `bantime.formula` in Fail2Ban 1.1.1.
pub const DEFAULT_FORMULA: &str = "ban.Time * (1<<(ban.Count if ban.Count<20 else 20)) * banFactor";

const MAX_EXPR_DEPTH: usize = 64;

/// Per-jail `bantime.*` incremental ban configuration and evaluator.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct BanTimeExtra {
    increment: Option<bool>,
    factor: Option<String>,
    formula: Option<String>,
    multipliers: Option<(String, Vec<i64>)>,
    maxtime: Option<i64>,
    rndtime: Option<i64>,
    overalljails: Option<PickleValue>,
}

impl BanTimeExtra {
    pub fn new() -> Self {
        Self::default()
    }

    /// Set one `bantime.<opt>` option from a wire [`PickleValue`], preserving upstream value types.
    pub fn set_opt_value(&mut self, opt: &str, value: &PickleValue) -> Result<()> {
        if opt == "overalljails" {
            self.overalljails = match value {
                PickleValue::None => None,
                PickleValue::Str(s) if s.is_empty() => None,
                PickleValue::Bool(b) => Some(PickleValue::Bool(*b)),
                PickleValue::Str(s) => Some(PickleValue::Str(s.clone())),
                other => Some(PickleValue::Str(other.to_string_lossy())),
            };
            return Ok(());
        }
        let raw = (value != &PickleValue::None).then(|| value.to_string_lossy());
        self.set_opt(opt, raw.as_deref())
    }

    /// Set one `bantime.<opt>` option, validating syntax/durations immediately.
    pub fn set_opt(&mut self, opt: &str, value: Option<&str>) -> Result<()> {
        let val = value.map(str::trim).filter(|s| !s.is_empty());
        match opt {
            "increment" => {
                self.increment = Some(val.map(parse_bool).transpose()?.unwrap_or(false));
            }
            "overalljails" => {
                self.overalljails = val.map(|s| PickleValue::Str(s.to_owned()));
            }
            "factor" => {
                if let Some(v) = val {
                    let evaluated = eval_formula(v, 600, 1, 1.0)?;
                    if !evaluated.is_finite() {
                        return Err(Error::config(format!("non-finite bantime.factor: {v:?}")));
                    }
                }
                self.factor = val.map(str::to_owned);
            }
            "formula" => {
                if let Some(v) = val {
                    let tokens = tokenize(v)?;
                    let mut parser = Parser::new(&tokens);
                    let expr = parser.parse_full()?;
                    validate_expr(&expr)?;
                    self.formula = Some(v.to_owned());
                } else {
                    self.formula = None;
                }
            }
            "multipliers" => {
                self.multipliers = if let Some(v) = val {
                    let mults: Result<Vec<i64>> = v
                        .split(' ')
                        .map(|part| {
                            part.parse().map_err(|_| {
                                Error::config(format!("invalid bantime.multipliers value {part:?}"))
                            })
                        })
                        .collect();
                    Some((v.to_owned(), mults?))
                } else {
                    None
                };
            }
            "maxtime" => {
                self.maxtime = match val {
                    Some(v) => Some(str2seconds_i64(v)?),
                    None => None,
                };
            }
            "rndtime" => {
                self.rndtime = match val {
                    Some(v) => Some(str2seconds_i64(v)?),
                    None => None,
                };
            }
            _ => {
                return Err(Error::invalid_command(format!(
                    "Unknown bantime option {opt:?}"
                )));
            }
        }
        Ok(())
    }

    /// Retrieve a configured option in the same type Fail2Ban reports on the socket.
    pub fn get_opt(&self, opt: &str) -> Option<PickleValue> {
        use PickleValue::{Bool, Int, Str};
        match opt {
            "increment" => self.increment.map(Bool),
            "overalljails" => self.overalljails.clone(),
            "factor" => self.factor.clone().map(Str),
            "formula" => self.formula.clone().map(Str),
            "multipliers" => self.multipliers.as_ref().map(|(raw, _)| Str(raw.clone())),
            "maxtime" => self.maxtime.map(Int),
            "rndtime" => self.rndtime.map(Int),
            _ => None,
        }
    }

    pub fn increment(&self) -> bool {
        self.increment.unwrap_or(false)
    }

    pub fn overall_jails(&self) -> bool {
        match &self.overalljails {
            None | Some(PickleValue::None) => false,
            Some(PickleValue::Bool(b)) => *b,
            Some(PickleValue::Int(n)) => *n != 0,
            Some(PickleValue::Str(s)) => parse_bool(s).unwrap_or(!s.is_empty()),
            Some(_) => true,
        }
    }

    /// Maximum ban time allowed for this jail (`Jail.getMaxBanTime`).
    pub fn max_ban_time(&self, default_ban_time: i64) -> i64 {
        if self.increment() {
            self.maxtime.unwrap_or(-1)
        } else {
            default_ban_time
        }
    }

    /// Calculate escalated ban duration in seconds (truncated like Python `int(...)`).
    pub fn calc_ban_time(&self, base_ban_time: i64, ban_count: u64, apply_rnd: bool) -> i64 {
        if base_ban_time < 0 {
            return base_ban_time;
        }
        let factor = self.factor.as_deref().unwrap_or("1");
        let ban_factor = eval_formula(factor, base_ban_time, ban_count, 1.0).unwrap_or(1.0);
        let mut val = if let Some((_, multipliers)) = &self.multipliers {
            let mult = usize::try_from(ban_count)
                .ok()
                .and_then(|idx| multipliers.get(idx))
                .or_else(|| multipliers.last())
                .copied()
                .unwrap_or(1);
            (base_ban_time as f64) * ban_factor * (mult as f64)
        } else {
            let formula = self.formula.as_deref().unwrap_or(DEFAULT_FORMULA);
            let evaluated = eval_formula(formula, base_ban_time, ban_count, ban_factor)
                .unwrap_or(base_ban_time as f64);
            evaluated.max(base_ban_time as f64)
        };

        if let Some(max_t) = self.maxtime
            && max_t >= 0
        {
            val = val.min(max_t as f64);
        }
        if apply_rnd
            && let Some(rnd_t) = self.rndtime
            && rnd_t > 0
        {
            val += random_unit_f64() * (rnd_t as f64);
        }

        if !val.is_finite() || val >= (i64::MAX as f64) {
            i64::MAX
        } else if val <= 0.0 {
            0
        } else {
            val.trunc() as i64
        }
    }
}

/// Exact Fail2Ban 1.1.1 retry boost for known bad IPs (`observer.py` line 388):
/// `min(((1 << min(ban_count, 20)) / 2 + 1), max_retry)`.
pub fn observer_retry_boost(ban_count: u64, max_retry: u64) -> u64 {
    let shifted = 1_u64 << ban_count.min(20);
    (shifted / 2 + 1).min(max_retry)
}

/// Check `db` for prior bans of `ticket.fid` and compute the escalated ban duration (`ObserverThread.incrBanTime`).
pub fn incr_ban_time(
    extra: &BanTimeExtra,
    db: Option<&Fail2BanDb>,
    jail: &str,
    base_ban_time: i64,
    ticket: &mut Ticket,
) -> i64 {
    if base_ban_time <= 0 || !extra.increment() {
        return base_ban_time;
    }
    let Some(db) = db else {
        return base_ban_time;
    };
    let Ok(Some((ban_count, time_of_ban, _last_ban_time))) =
        db.get_ban(&ticket.fid, Some(jail), extra.overall_jails())
    else {
        return base_ban_time;
    };

    if ban_count >= ticket.ban_count {
        ticket.ban_count = ban_count.saturating_add(1);
    }
    let new_ban_time = if ban_count > 0 {
        extra.calc_ban_time(base_ban_time, ban_count, true)
    } else {
        base_ban_time
    };
    ticket.ban_time = Some(new_ban_time);
    if ticket.time <= time_of_ban as f64 {
        ticket.restored = true;
    }
    new_ban_time
}

/// Compute the extra retry boost to feed back to `FailManager` when a known bad IP fails again (`ObserverThread.failureFound`).
///
/// Returns `0` when no extra boost applies (or ticket timestamp is not newer than the last DB ban).
pub fn failure_found_boost(
    extra: &BanTimeExtra,
    db: Option<&Fail2BanDb>,
    jail: &str,
    ticket: &mut Ticket,
    max_retry: u64,
) -> u64 {
    if !extra.increment() {
        return 0;
    }
    let Some(db) = db else {
        return 0;
    };
    let Ok(Some((db_ban_count, time_of_ban, _last_ban_time))) =
        db.get_ban(&ticket.fid, Some(jail), false)
    else {
        return 0;
    };
    if ticket.time <= time_of_ban as f64 {
        return 0;
    }
    let ban_count = db_ban_count.max(ticket.ban_count);
    let retry_count = observer_retry_boost(ban_count, max_retry);
    if retry_count <= 1 {
        return 0;
    }
    if ban_count > ticket.ban_count {
        ticket.ban_count = ban_count;
    }
    retry_count - 1
}

/// Evaluate a Fail2Ban `bantime.formula` / `bantime.factor` expression.
pub fn eval_formula(expr: &str, ban_time: i64, ban_count: u64, ban_factor: f64) -> Result<f64> {
    let tokens = tokenize(expr)?;
    let mut parser = Parser::new(&tokens);
    let ast = parser.parse_full()?;
    let env = EvalEnv {
        ban_time,
        ban_count: i64::try_from(ban_count).unwrap_or(i64::MAX),
        ban_factor,
    };
    let val = eval_ast(&ast, &env)?;
    let out = val.as_f64();
    if !out.is_finite() {
        return Err(Error::config(format!(
            "formula evaluated to non-finite value: {expr:?}"
        )));
    }
    Ok(out)
}

fn random_unit_f64() -> f64 {
    let mut buf = [0_u8; 8];
    if let Ok(mut f) = File::open("/dev/urandom")
        && f.read_exact(&mut buf).is_ok()
    {
        let bits = u64::from_le_bytes(buf) >> 11;
        return (bits as f64) / ((1_u64 << 53) as f64);
    }
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    f64::from(nanos) / 1_000_000_000.0
}

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Int(i64),
    Float(f64),
    Ident(String),
    Plus,
    Minus,
    Star,
    Pow,
    Slash,
    FloorDiv,
    Percent,
    Shl,
    Shr,
    Lt,
    Le,
    Gt,
    Ge,
    Eq,
    Ne,
    LParen,
    RParen,
    Comma,
    KwAnd,
    KwOr,
    KwNot,
    KwIf,
    KwElse,
}

fn tokenize(input: &str) -> Result<Vec<Tok>> {
    let bytes = input.as_bytes();
    let mut i = 0;
    let mut out = Vec::new();

    while i < bytes.len() {
        let b = bytes[i];
        if b.is_ascii_whitespace() {
            i += 1;
            continue;
        }
        if b.is_ascii_digit() || (b == b'.' && i + 1 < bytes.len() && bytes[i + 1].is_ascii_digit())
        {
            let start = i;
            let mut is_float = b == b'.';
            while i < bytes.len() && (bytes[i].is_ascii_digit() || bytes[i] == b'.') {
                if bytes[i] == b'.' {
                    is_float = true;
                }
                i += 1;
            }
            if i < bytes.len() && matches!(bytes[i], b'e' | b'E') {
                is_float = true;
                i += 1;
                if i < bytes.len() && matches!(bytes[i], b'+' | b'-') {
                    i += 1;
                }
                let exp_start = i;
                while i < bytes.len() && bytes[i].is_ascii_digit() {
                    i += 1;
                }
                if i == exp_start {
                    return Err(Error::config(format!(
                        "invalid scientific notation in formula {input:?}"
                    )));
                }
            }
            let lexeme = &input[start..i];
            if !is_float && let Ok(n) = lexeme.parse::<i64>() {
                out.push(Tok::Int(n));
                continue;
            }
            let f: f64 = lexeme.parse().map_err(|_| {
                Error::config(format!("invalid numeric literal {lexeme:?} in {input:?}"))
            })?;
            out.push(Tok::Float(f));
            continue;
        }
        if b.is_ascii_alphabetic() || b == b'_' {
            let start = i;
            i += 1;
            while i < bytes.len()
                && (bytes[i].is_ascii_alphanumeric() || matches!(bytes[i], b'_' | b'.'))
            {
                i += 1;
            }
            let word = &input[start..i];
            if word.ends_with('.') || word.contains("..") {
                return Err(Error::config(format!(
                    "invalid identifier {word:?} in formula {input:?}"
                )));
            }
            let tok = match word {
                "and" => Tok::KwAnd,
                "or" => Tok::KwOr,
                "not" => Tok::KwNot,
                "if" => Tok::KwIf,
                "else" => Tok::KwElse,
                _ => Tok::Ident(word.to_owned()),
            };
            out.push(tok);
            continue;
        }
        let two = bytes.get(i..i + 2);
        match two {
            Some(b"**") => {
                out.push(Tok::Pow);
                i += 2;
                continue;
            }
            Some(b"//") => {
                out.push(Tok::FloorDiv);
                i += 2;
                continue;
            }
            Some(b"<<") => {
                out.push(Tok::Shl);
                i += 2;
                continue;
            }
            Some(b">>") => {
                out.push(Tok::Shr);
                i += 2;
                continue;
            }
            Some(b"<=") => {
                out.push(Tok::Le);
                i += 2;
                continue;
            }
            Some(b">=") => {
                out.push(Tok::Ge);
                i += 2;
                continue;
            }
            Some(b"==") => {
                out.push(Tok::Eq);
                i += 2;
                continue;
            }
            Some(b"!=") => {
                out.push(Tok::Ne);
                i += 2;
                continue;
            }
            _ => {}
        }
        match b {
            b'+' => out.push(Tok::Plus),
            b'-' => out.push(Tok::Minus),
            b'*' => out.push(Tok::Star),
            b'/' => out.push(Tok::Slash),
            b'%' => out.push(Tok::Percent),
            b'<' => out.push(Tok::Lt),
            b'>' => out.push(Tok::Gt),
            b'(' => out.push(Tok::LParen),
            b')' => out.push(Tok::RParen),
            b',' => out.push(Tok::Comma),
            _ => {
                return Err(Error::config(format!(
                    "unexpected character {:?} in formula {input:?}",
                    b as char
                )));
            }
        }
        i += 1;
    }

    if out.is_empty() {
        return Err(Error::config("empty formula expression"));
    }
    Ok(out)
}

#[derive(Debug, Clone, Copy)]
enum Val {
    Int(i64),
    Float(f64),
    Bool(bool),
}

impl Val {
    fn as_f64(self) -> f64 {
        match self {
            Self::Int(i) => i as f64,
            Self::Float(f) => f,
            Self::Bool(b) => {
                if b {
                    1.0
                } else {
                    0.0
                }
            }
        }
    }

    fn as_bool(self) -> bool {
        match self {
            Self::Int(i) => i != 0,
            Self::Float(f) => f != 0.0,
            Self::Bool(b) => b,
        }
    }

    fn as_int_exact(self) -> Result<i64> {
        match self {
            Self::Int(i) => Ok(i),
            Self::Bool(b) => Ok(i64::from(b)),
            Self::Float(_) => Err(Error::config(
                "integer operand required for bitwise shift operator",
            )),
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum UnaryOp {
    Plus,
    Minus,
    Not,
}

#[derive(Debug, Clone, Copy)]
enum BinOp {
    Add,
    Sub,
    Mul,
    Div,
    FloorDiv,
    Mod,
    Pow,
    Shl,
    Shr,
}

#[derive(Debug, Clone, Copy)]
enum CmpOp {
    Lt,
    Le,
    Gt,
    Ge,
    Eq,
    Ne,
}

#[derive(Debug, Clone, Copy)]
enum LogicOp {
    And,
    Or,
}

#[derive(Debug, Clone)]
enum Expr {
    Lit(Val),
    Var(String),
    Call {
        func: String,
        args: Vec<Expr>,
    },
    Unary {
        op: UnaryOp,
        expr: Box<Expr>,
    },
    Binary {
        op: BinOp,
        lhs: Box<Expr>,
        rhs: Box<Expr>,
    },
    Compare {
        first: Box<Expr>,
        rest: Vec<(CmpOp, Expr)>,
    },
    Logic {
        op: LogicOp,
        lhs: Box<Expr>,
        rhs: Box<Expr>,
    },
    Ternary {
        body: Box<Expr>,
        cond: Box<Expr>,
        orelse: Box<Expr>,
    },
}

struct Parser<'a> {
    toks: &'a [Tok],
    pos: usize,
    depth: usize,
}

impl<'a> Parser<'a> {
    fn new(toks: &'a [Tok]) -> Self {
        Self {
            toks,
            pos: 0,
            depth: 0,
        }
    }

    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.pos)
    }

    fn bump(&mut self) -> Option<&Tok> {
        let tok = self.toks.get(self.pos)?;
        self.pos += 1;
        Some(tok)
    }

    fn enter(&mut self) -> Result<()> {
        self.depth += 1;
        if self.depth > MAX_EXPR_DEPTH {
            return Err(Error::config("formula expression nesting limit exceeded"));
        }
        Ok(())
    }

    fn leave(&mut self) {
        self.depth = self.depth.saturating_sub(1);
    }

    fn parse_full(&mut self) -> Result<Expr> {
        let expr = self.parse_ternary()?;
        if self.pos != self.toks.len() {
            return Err(Error::config(format!(
                "unexpected trailing token {:?} in formula",
                self.toks.get(self.pos)
            )));
        }
        Ok(expr)
    }

    fn parse_ternary(&mut self) -> Result<Expr> {
        self.enter()?;
        let body = self.parse_or();
        if body.is_err() {
            self.leave();
            return body;
        }
        let body = body?;
        let out = if matches!(self.peek(), Some(Tok::KwIf)) {
            self.bump();
            let cond = self.parse_or()?;
            if !matches!(self.peek(), Some(Tok::KwElse)) {
                self.leave();
                return Err(Error::config("expected 'else' in conditional expression"));
            }
            self.bump();
            let orelse = self.parse_ternary()?;
            Ok(Expr::Ternary {
                body: Box::new(body),
                cond: Box::new(cond),
                orelse: Box::new(orelse),
            })
        } else {
            Ok(body)
        };
        self.leave();
        out
    }

    fn parse_or(&mut self) -> Result<Expr> {
        let mut lhs = self.parse_and()?;
        while matches!(self.peek(), Some(Tok::KwOr)) {
            self.bump();
            let rhs = self.parse_and()?;
            lhs = Expr::Logic {
                op: LogicOp::Or,
                lhs: Box::new(lhs),
                rhs: Box::new(rhs),
            };
        }
        Ok(lhs)
    }

    fn parse_and(&mut self) -> Result<Expr> {
        let mut lhs = self.parse_not()?;
        while matches!(self.peek(), Some(Tok::KwAnd)) {
            self.bump();
            let rhs = self.parse_not()?;
            lhs = Expr::Logic {
                op: LogicOp::And,
                lhs: Box::new(lhs),
                rhs: Box::new(rhs),
            };
        }
        Ok(lhs)
    }

    fn parse_not(&mut self) -> Result<Expr> {
        self.enter()?;
        let res = if matches!(self.peek(), Some(Tok::KwNot)) {
            self.bump();
            let inner = self.parse_not()?;
            Ok(Expr::Unary {
                op: UnaryOp::Not,
                expr: Box::new(inner),
            })
        } else {
            self.parse_cmp()
        };
        self.leave();
        res
    }

    fn parse_cmp(&mut self) -> Result<Expr> {
        let first = self.parse_shift()?;
        let mut rest = Vec::new();
        while let Some(op) = self.peek().and_then(|t| match t {
            Tok::Lt => Some(CmpOp::Lt),
            Tok::Le => Some(CmpOp::Le),
            Tok::Gt => Some(CmpOp::Gt),
            Tok::Ge => Some(CmpOp::Ge),
            Tok::Eq => Some(CmpOp::Eq),
            Tok::Ne => Some(CmpOp::Ne),
            _ => None,
        }) {
            self.bump();
            let rhs = self.parse_shift()?;
            rest.push((op, rhs));
        }
        if rest.is_empty() {
            Ok(first)
        } else {
            Ok(Expr::Compare {
                first: Box::new(first),
                rest,
            })
        }
    }

    fn parse_shift(&mut self) -> Result<Expr> {
        let mut lhs = self.parse_add_sub()?;
        while let Some(op) = self.peek().and_then(|t| match t {
            Tok::Shl => Some(BinOp::Shl),
            Tok::Shr => Some(BinOp::Shr),
            _ => None,
        }) {
            self.bump();
            let rhs = self.parse_add_sub()?;
            lhs = Expr::Binary {
                op,
                lhs: Box::new(lhs),
                rhs: Box::new(rhs),
            };
        }
        Ok(lhs)
    }

    fn parse_add_sub(&mut self) -> Result<Expr> {
        let mut lhs = self.parse_mul_div()?;
        while let Some(op) = self.peek().and_then(|t| match t {
            Tok::Plus => Some(BinOp::Add),
            Tok::Minus => Some(BinOp::Sub),
            _ => None,
        }) {
            self.bump();
            let rhs = self.parse_mul_div()?;
            lhs = Expr::Binary {
                op,
                lhs: Box::new(lhs),
                rhs: Box::new(rhs),
            };
        }
        Ok(lhs)
    }

    fn parse_mul_div(&mut self) -> Result<Expr> {
        let mut lhs = self.parse_unary()?;
        while let Some(op) = self.peek().and_then(|t| match t {
            Tok::Star => Some(BinOp::Mul),
            Tok::Slash => Some(BinOp::Div),
            Tok::FloorDiv => Some(BinOp::FloorDiv),
            Tok::Percent => Some(BinOp::Mod),
            _ => None,
        }) {
            self.bump();
            let rhs = self.parse_unary()?;
            lhs = Expr::Binary {
                op,
                lhs: Box::new(lhs),
                rhs: Box::new(rhs),
            };
        }
        Ok(lhs)
    }

    fn parse_unary(&mut self) -> Result<Expr> {
        self.enter()?;
        let res = match self.peek() {
            Some(Tok::Plus) => {
                self.bump();
                let inner = self.parse_unary()?;
                Ok(Expr::Unary {
                    op: UnaryOp::Plus,
                    expr: Box::new(inner),
                })
            }
            Some(Tok::Minus) => {
                self.bump();
                let inner = self.parse_unary()?;
                Ok(Expr::Unary {
                    op: UnaryOp::Minus,
                    expr: Box::new(inner),
                })
            }
            _ => self.parse_power(),
        };
        self.leave();
        res
    }

    fn parse_power(&mut self) -> Result<Expr> {
        let lhs = self.parse_primary()?;
        if matches!(self.peek(), Some(Tok::Pow)) {
            self.bump();
            let rhs = self.parse_unary()?;
            Ok(Expr::Binary {
                op: BinOp::Pow,
                lhs: Box::new(lhs),
                rhs: Box::new(rhs),
            })
        } else {
            Ok(lhs)
        }
    }

    fn parse_primary(&mut self) -> Result<Expr> {
        match self.bump().cloned() {
            Some(Tok::Int(i)) => Ok(Expr::Lit(Val::Int(i))),
            Some(Tok::Float(f)) => Ok(Expr::Lit(Val::Float(f))),
            Some(Tok::Ident(name)) => {
                if matches!(self.peek(), Some(Tok::LParen)) {
                    self.bump();
                    let mut args = Vec::new();
                    if !matches!(self.peek(), Some(Tok::RParen)) {
                        loop {
                            args.push(self.parse_ternary()?);
                            if matches!(self.peek(), Some(Tok::Comma)) {
                                self.bump();
                                if matches!(self.peek(), Some(Tok::RParen)) {
                                    break;
                                }
                            } else {
                                break;
                            }
                        }
                    }
                    if !matches!(self.peek(), Some(Tok::RParen)) {
                        return Err(Error::config(format!(
                            "unclosed argument list in call to {name:?}"
                        )));
                    }
                    self.bump();
                    Ok(Expr::Call { func: name, args })
                } else {
                    Ok(Expr::Var(name))
                }
            }
            Some(Tok::LParen) => {
                let inner = self.parse_ternary()?;
                if !matches!(self.peek(), Some(Tok::RParen)) {
                    return Err(Error::config("unclosed '(' in formula expression"));
                }
                self.bump();
                Ok(inner)
            }
            other => Err(Error::config(format!(
                "unexpected token {other:?} in formula expression"
            ))),
        }
    }
}

fn validate_expr(expr: &Expr) -> Result<()> {
    match expr {
        Expr::Lit(_) => Ok(()),
        Expr::Var(name) => match name.as_str() {
            "ban.Time" | "ban.Count" | "banFactor" | "math.pi" | "math.e" | "True" | "False" => {
                Ok(())
            }
            _ => Err(Error::config(format!(
                "unknown variable {name:?} in bantime.formula"
            ))),
        },
        Expr::Call { func, args } => {
            let arity_ok = match func.as_str() {
                "math.exp" | "math.sqrt" | "math.ceil" | "math.floor" | "int" | "float" | "abs" => {
                    args.len() == 1
                }
                "math.log" | "round" => matches!(args.len(), 1 | 2),
                "math.pow" => args.len() == 2,
                "min" | "max" => !args.is_empty(),
                _ => {
                    return Err(Error::config(format!(
                        "unsupported function {func:?} in bantime.formula"
                    )));
                }
            };
            if !arity_ok {
                return Err(Error::config(format!(
                    "wrong number of arguments for {func:?} in bantime.formula"
                )));
            }
            for arg in args {
                validate_expr(arg)?;
            }
            Ok(())
        }
        Expr::Unary { expr, .. } => validate_expr(expr),
        Expr::Binary { lhs, rhs, .. } | Expr::Logic { lhs, rhs, .. } => {
            validate_expr(lhs)?;
            validate_expr(rhs)
        }
        Expr::Compare { first, rest } => {
            validate_expr(first)?;
            for (_, rhs) in rest {
                validate_expr(rhs)?;
            }
            Ok(())
        }
        Expr::Ternary { body, cond, orelse } => {
            validate_expr(body)?;
            validate_expr(cond)?;
            validate_expr(orelse)
        }
    }
}

struct EvalEnv {
    ban_time: i64,
    ban_count: i64,
    ban_factor: f64,
}

fn eval_ast(expr: &Expr, env: &EvalEnv) -> Result<Val> {
    match expr {
        Expr::Lit(v) => Ok(*v),
        Expr::Var(name) => match name.as_str() {
            "ban.Time" => Ok(Val::Int(env.ban_time)),
            "ban.Count" => Ok(Val::Int(env.ban_count)),
            "banFactor" => Ok(
                if env.ban_factor.fract() == 0.0
                    && env.ban_factor >= (i64::MIN as f64)
                    && env.ban_factor <= (i64::MAX as f64)
                {
                    Val::Int(env.ban_factor as i64)
                } else {
                    Val::Float(env.ban_factor)
                },
            ),
            "math.pi" => Ok(Val::Float(std::f64::consts::PI)),
            "math.e" => Ok(Val::Float(std::f64::consts::E)),
            "True" => Ok(Val::Bool(true)),
            "False" => Ok(Val::Bool(false)),
            _ => Err(Error::config(format!("unknown variable {name:?}"))),
        },
        Expr::Call { func, args } => eval_call(func, args, env),
        Expr::Unary { op, expr } => {
            let v = eval_ast(expr, env)?;
            match op {
                UnaryOp::Plus => match v {
                    Val::Bool(b) => Ok(Val::Int(i64::from(b))),
                    other => Ok(other),
                },
                UnaryOp::Minus => match v {
                    Val::Int(i) => Ok(i
                        .checked_neg()
                        .map_or_else(|| Val::Float(-(i as f64)), Val::Int)),
                    Val::Float(f) => Ok(Val::Float(-f)),
                    Val::Bool(b) => Ok(Val::Int(-i64::from(b))),
                },
                UnaryOp::Not => Ok(Val::Bool(!v.as_bool())),
            }
        }
        Expr::Binary { op, lhs, rhs } => {
            let l = eval_ast(lhs, env)?;
            let r = eval_ast(rhs, env)?;
            eval_binary(*op, l, r)
        }
        Expr::Compare { first, rest } => {
            let mut prev = eval_ast(first, env)?;
            for (op, rhs_expr) in rest {
                let next = eval_ast(rhs_expr, env)?;
                if !eval_cmp(*op, prev, next) {
                    return Ok(Val::Bool(false));
                }
                prev = next;
            }
            Ok(Val::Bool(true))
        }
        Expr::Logic { op, lhs, rhs } => {
            let l = eval_ast(lhs, env)?;
            match op {
                LogicOp::And => {
                    if !l.as_bool() {
                        Ok(l)
                    } else {
                        eval_ast(rhs, env)
                    }
                }
                LogicOp::Or => {
                    if l.as_bool() {
                        Ok(l)
                    } else {
                        eval_ast(rhs, env)
                    }
                }
            }
        }
        Expr::Ternary { body, cond, orelse } => {
            if eval_ast(cond, env)?.as_bool() {
                eval_ast(body, env)
            } else {
                eval_ast(orelse, env)
            }
        }
    }
}

fn eval_call(func: &str, args: &[Expr], env: &EvalEnv) -> Result<Val> {
    let mut vals = Vec::with_capacity(args.len());
    for a in args {
        vals.push(eval_ast(a, env)?);
    }
    match func {
        "math.exp" => {
            let [x] = vals.as_slice() else {
                return Err(Error::config("math.exp expects 1 argument"));
            };
            Ok(Val::Float(x.as_f64().exp()))
        }
        "math.log" => match vals.as_slice() {
            [x] => {
                let xf = x.as_f64();
                if xf <= 0.0 {
                    return Err(Error::config("math.log domain error"));
                }
                Ok(Val::Float(xf.ln()))
            }
            [x, base] => {
                let xf = x.as_f64();
                let bf = base.as_f64();
                if xf <= 0.0 || bf <= 0.0 || bf == 1.0 {
                    return Err(Error::config("math.log domain error"));
                }
                Ok(Val::Float(xf.ln() / bf.ln()))
            }
            _ => Err(Error::config("math.log expects 1 or 2 arguments")),
        },
        "math.pow" => {
            let [x, y] = vals.as_slice() else {
                return Err(Error::config("math.pow expects 2 arguments"));
            };
            Ok(Val::Float(x.as_f64().powf(y.as_f64())))
        }
        "math.sqrt" => {
            let [x] = vals.as_slice() else {
                return Err(Error::config("math.sqrt expects 1 argument"));
            };
            let xf = x.as_f64();
            if xf < 0.0 {
                return Err(Error::config("math.sqrt domain error"));
            }
            Ok(Val::Float(xf.sqrt()))
        }
        "math.ceil" => {
            let [x] = vals.as_slice() else {
                return Err(Error::config("math.ceil expects 1 argument"));
            };
            Ok(float_to_int_or_float(x.as_f64().ceil()))
        }
        "math.floor" => {
            let [x] = vals.as_slice() else {
                return Err(Error::config("math.floor expects 1 argument"));
            };
            Ok(float_to_int_or_float(x.as_f64().floor()))
        }
        "min" => {
            let Some((&first, rest)) = vals.split_first() else {
                return Err(Error::config("min expects at least 1 argument"));
            };
            let mut best = first;
            for &v in rest {
                if eval_cmp(CmpOp::Lt, v, best) {
                    best = v;
                }
            }
            Ok(best)
        }
        "max" => {
            let Some((&first, rest)) = vals.split_first() else {
                return Err(Error::config("max expects at least 1 argument"));
            };
            let mut best = first;
            for &v in rest {
                if eval_cmp(CmpOp::Gt, v, best) {
                    best = v;
                }
            }
            Ok(best)
        }
        "int" => {
            let [x] = vals.as_slice() else {
                return Err(Error::config("int expects 1 argument"));
            };
            match x {
                Val::Int(i) => Ok(Val::Int(*i)),
                Val::Bool(b) => Ok(Val::Int(i64::from(*b))),
                Val::Float(f) => Ok(float_to_int_or_float(f.trunc())),
            }
        }
        "float" => {
            let [x] = vals.as_slice() else {
                return Err(Error::config("float expects 1 argument"));
            };
            Ok(Val::Float(x.as_f64()))
        }
        "abs" => {
            let [x] = vals.as_slice() else {
                return Err(Error::config("abs expects 1 argument"));
            };
            match x {
                Val::Int(i) => Ok(i
                    .checked_abs()
                    .map_or_else(|| Val::Float((*i as f64).abs()), Val::Int)),
                Val::Bool(b) => Ok(Val::Int(i64::from(*b))),
                Val::Float(f) => Ok(Val::Float(f.abs())),
            }
        }
        "round" => match vals.as_slice() {
            [x] => match x {
                Val::Int(i) => Ok(Val::Int(*i)),
                Val::Bool(b) => Ok(Val::Int(i64::from(*b))),
                Val::Float(f) => Ok(float_to_int_or_float(f.round_ties_even())),
            },
            [x, nd] => {
                let digits = nd.as_int_exact()?;
                let digits_i32 =
                    i32::try_from(digits).unwrap_or(if digits < 0 { -308 } else { 308 });
                let scale = 10.0_f64.powi(digits_i32);
                Ok(Val::Float((x.as_f64() * scale).round_ties_even() / scale))
            }
            _ => Err(Error::config("round expects 1 or 2 arguments")),
        },
        _ => Err(Error::config(format!("unsupported function {func:?}"))),
    }
}

fn float_to_int_or_float(f: f64) -> Val {
    if f.is_finite() && f >= (i64::MIN as f64) && f < (i64::MAX as f64) {
        Val::Int(f as i64)
    } else {
        Val::Float(f)
    }
}

fn to_int_pair(l: Val, r: Val) -> Option<(i64, i64)> {
    match (l, r) {
        (Val::Int(a), Val::Int(b)) => Some((a, b)),
        (Val::Int(a), Val::Bool(b)) => Some((a, i64::from(b))),
        (Val::Bool(a), Val::Int(b)) => Some((i64::from(a), b)),
        (Val::Bool(a), Val::Bool(b)) => Some((i64::from(a), i64::from(b))),
        _ => None,
    }
}

fn eval_binary(op: BinOp, l: Val, r: Val) -> Result<Val> {
    match op {
        BinOp::Add => Ok(match to_int_pair(l, r) {
            Some((a, b)) => a
                .checked_add(b)
                .map_or_else(|| Val::Float(a as f64 + b as f64), Val::Int),
            None => Val::Float(l.as_f64() + r.as_f64()),
        }),
        BinOp::Sub => Ok(match to_int_pair(l, r) {
            Some((a, b)) => a
                .checked_sub(b)
                .map_or_else(|| Val::Float(a as f64 - b as f64), Val::Int),
            None => Val::Float(l.as_f64() - r.as_f64()),
        }),
        BinOp::Mul => Ok(match to_int_pair(l, r) {
            Some((a, b)) => a
                .checked_mul(b)
                .map_or_else(|| Val::Float(a as f64 * b as f64), Val::Int),
            None => Val::Float(l.as_f64() * r.as_f64()),
        }),
        BinOp::Div => {
            let rf = r.as_f64();
            if rf == 0.0 {
                return Err(Error::config("division by zero in formula"));
            }
            Ok(Val::Float(l.as_f64() / rf))
        }
        BinOp::FloorDiv => {
            if let Some((a, b)) = to_int_pair(l, r) {
                if b == 0 {
                    return Err(Error::config("integer division by zero in formula"));
                }
                if a == i64::MIN && b == -1 {
                    return Ok(Val::Float((a as f64 / b as f64).floor()));
                }
                let q = a / b;
                let rem = a % b;
                let floor_q = if rem != 0 && ((rem < 0) != (b < 0)) {
                    q - 1
                } else {
                    q
                };
                return Ok(Val::Int(floor_q));
            }
            let rf = r.as_f64();
            if rf == 0.0 {
                return Err(Error::config("floor division by zero in formula"));
            }
            Ok(Val::Float((l.as_f64() / rf).floor()))
        }
        BinOp::Mod => {
            if let Some((a, b)) = to_int_pair(l, r) {
                if b == 0 {
                    return Err(Error::config("integer modulo by zero in formula"));
                }
                if a == i64::MIN && b == -1 {
                    return Ok(Val::Int(0));
                }
                let rem = a % b;
                let py_rem = if rem != 0 && ((rem < 0) != (b < 0)) {
                    rem + b
                } else {
                    rem
                };
                return Ok(Val::Int(py_rem));
            }
            let rf = r.as_f64();
            if rf == 0.0 {
                return Err(Error::config("modulo by zero in formula"));
            }
            let lf = l.as_f64();
            Ok(Val::Float(lf - (lf / rf).floor() * rf))
        }
        BinOp::Pow => {
            if let Some((a, b)) = to_int_pair(l, r) {
                if b >= 0 {
                    if let Ok(exp) = u32::try_from(b)
                        && let Some(res) = a.checked_pow(exp)
                    {
                        return Ok(Val::Int(res));
                    }
                    return Ok(Val::Float((a as f64).powf(b as f64)));
                }
                if a == 0 {
                    return Err(Error::config("0.0 cannot be raised to a negative power"));
                }
                return Ok(Val::Float((a as f64).powf(b as f64)));
            }
            Ok(Val::Float(l.as_f64().powf(r.as_f64())))
        }
        BinOp::Shl => {
            let a = l.as_int_exact()?;
            let b = r.as_int_exact()?;
            if b < 0 {
                return Err(Error::config("negative shift count in formula"));
            }
            if b < 63
                && let Some(res) = a.checked_shl(b as u32)
            {
                return Ok(Val::Int(res));
            }
            Ok(Val::Float((a as f64) * 2.0_f64.powf(b as f64)))
        }
        BinOp::Shr => {
            let a = l.as_int_exact()?;
            let b = r.as_int_exact()?;
            if b < 0 {
                return Err(Error::config("negative shift count in formula"));
            }
            if b >= 64 {
                Ok(Val::Int(if a < 0 { -1 } else { 0 }))
            } else {
                Ok(Val::Int(a >> b))
            }
        }
    }
}

fn eval_cmp(op: CmpOp, l: Val, r: Val) -> bool {
    if let Some((a, b)) = to_int_pair(l, r) {
        return match op {
            CmpOp::Lt => a < b,
            CmpOp::Le => a <= b,
            CmpOp::Gt => a > b,
            CmpOp::Ge => a >= b,
            CmpOp::Eq => a == b,
            CmpOp::Ne => a != b,
        };
    }
    let lf = l.as_f64();
    let rf = r.as_f64();
    match op {
        CmpOp::Lt => lf < rf,
        CmpOp::Le => lf <= rf,
        CmpOp::Gt => lf > rf,
        CmpOp::Ge => lf >= rf,
        CmpOp::Eq => lf == rf,
        CmpOp::Ne => lf != rf,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::ticket::TicketId;

    #[test]
    fn default_formula_and_maxtime_match_upstream_observer_testcase() {
        let mut extra = BanTimeExtra::new();
        extra.set_opt("increment", Some("true")).unwrap();
        extra.set_opt("maxtime", Some("1d")).unwrap();
        assert_eq!(extra.get_opt("increment"), Some(PickleValue::Bool(true)));
        assert_eq!(extra.get_opt("maxtime"), Some(PickleValue::Int(86400)));

        let seq: Vec<i64> = (1..=10)
            .map(|c| extra.calc_ban_time(600, c, false))
            .collect();
        assert_eq!(
            seq,
            vec![
                1200, 2400, 4800, 9600, 19200, 38400, 76800, 86400, 86400, 86400
            ]
        );

        extra.set_opt("maxtime", Some("30d")).unwrap();
        let seq_30d: Vec<i64> = (1..=10)
            .map(|c| extra.calc_ban_time(600, c, false))
            .collect();
        assert_eq!(
            seq_30d,
            vec![
                1200, 2400, 4800, 9600, 19200, 38400, 76800, 153600, 307200, 614400
            ]
        );

        extra.set_opt("maxtime", Some("1d")).unwrap();
        extra.set_opt("factor", Some("1.33")).unwrap();
        let seq_float: Vec<i64> = (1..=10)
            .map(|c| extra.calc_ban_time(600, c, false))
            .collect();
        assert_eq!(
            seq_float,
            vec![
                1596, 3192, 6384, 12768, 25536, 51072, 86400, 86400, 86400, 86400
            ]
        );
    }

    #[test]
    fn multipliers_cap_at_last_entry_and_roundtrip_opt() {
        let mut extra = BanTimeExtra::new();
        extra.set_opt("increment", Some("true")).unwrap();
        extra.set_opt("maxtime", Some("30d")).unwrap();
        extra
            .set_opt("multipliers", Some("1 2 4 8 16 32 64 128 256"))
            .unwrap();
        assert_eq!(
            extra.get_opt("multipliers"),
            Some(PickleValue::Str("1 2 4 8 16 32 64 128 256".to_owned()))
        );

        let seq: Vec<i64> = (1..=10)
            .map(|c| extra.calc_ban_time(600, c, false))
            .collect();
        assert_eq!(
            seq,
            vec![
                1200, 2400, 4800, 9600, 19200, 38400, 76800, 153600, 153600, 153600
            ]
        );

        extra.set_opt("multipliers", None).unwrap();
        assert_eq!(extra.get_opt("multipliers"), None);
    }

    #[test]
    fn math_exp_formula_and_expression_factor_match_upstream() {
        let mut extra = BanTimeExtra::new();
        extra.set_opt("maxtime", Some("30d")).unwrap();
        extra
            .set_opt(
                "formula",
                Some("ban.Time * math.exp(float(ban.Count+1)*banFactor)/math.exp(1*banFactor)"),
            )
            .unwrap();
        extra.set_opt("factor", Some("2.0 / 2.885385")).unwrap();

        let seq_exp: Vec<i64> = (1..=10)
            .map(|c| extra.calc_ban_time(600, c, false))
            .collect();
        assert_eq!(
            seq_exp,
            vec![
                1200, 2400, 4800, 9600, 19200, 38400, 76800, 153601, 307203, 614407
            ]
        );

        extra.set_opt("maxtime", Some("24h")).unwrap();
        extra.set_opt("factor", Some("1")).unwrap();
        let seq_e: Vec<i64> = (1..=10)
            .map(|c| extra.calc_ban_time(600, c, false))
            .collect();
        assert_eq!(
            seq_e,
            vec![
                1630, 4433, 12051, 32758, 86400, 86400, 86400, 86400, 86400, 86400
            ]
        );
    }

    #[test]
    fn formula_evaluator_covers_all_operators_and_builtins() {
        assert_eq!(eval_formula("-2 ** 2 + 10", 1, 0, 1.0).unwrap(), 6.0);
        assert_eq!(eval_formula("2 ** -2", 1, 0, 1.0).unwrap(), 0.25);
        assert_eq!(eval_formula("2 ** 3 ** 2", 1, 0, 1.0).unwrap(), 512.0);
        assert_eq!(eval_formula("-7 // 2", 1, 0, 1.0).unwrap(), -4.0);
        assert_eq!(eval_formula("-7 % 3", 1, 0, 1.0).unwrap(), 2.0);
        assert_eq!(eval_formula("16 >> 2", 1, 0, 1.0).unwrap(), 4.0);
        assert_eq!(
            eval_formula(
                "0 if ban.Count == 0 else math.ceil(math.sqrt(math.pow(ban.Count, 2))) + math.floor(math.log(math.exp(2)))",
                10,
                3,
                1.0
            )
            .unwrap(),
            5.0
        );
        assert_eq!(
            eval_formula("min(10, max(2, int(3.9), abs(-4), round(4.5)))", 1, 0, 1.0).unwrap(),
            4.0
        );
        assert_eq!(
            eval_formula(
                "100 if 1 <= ban.Count <= 5 and not (ban.Count == 9) or False else 1",
                1,
                3,
                1.0
            )
            .unwrap(),
            100.0
        );
        // Division by zero inside untaken ternary branch must not trigger!
        assert_eq!(
            eval_formula("0 if ban.Count == 0 else 10 / ban.Count", 1, 0, 1.0).unwrap(),
            0.0
        );
    }

    #[test]
    fn rndtime_adds_bounded_jitter_when_enabled() {
        let mut extra = BanTimeExtra::new();
        extra.set_opt("increment", Some("true")).unwrap();
        extra.set_opt("rndtime", Some("5m")).unwrap();
        assert_eq!(extra.calc_ban_time(600, 1, false), 1200);
        let mut saw_jitter = false;
        for _ in 0..32 {
            let v = extra.calc_ban_time(600, 1, true);
            assert!((1200..=1500).contains(&v));
            if v > 1200 {
                saw_jitter = true;
            }
        }
        assert!(saw_jitter);
    }

    #[test]
    fn observer_retry_boost_and_db_integration() {
        assert_eq!(observer_retry_boost(0, 5), 1);
        assert_eq!(observer_retry_boost(1, 5), 2);
        assert_eq!(observer_retry_boost(2, 5), 3);
        assert_eq!(observer_retry_boost(3, 5), 5);
        assert_eq!(observer_retry_boost(4, 5), 5);
        assert_eq!(observer_retry_boost(4, 10), 9);
        assert_eq!(observer_retry_boost(25, 100), 100);

        let db = Fail2BanDb::open(":memory:", 86_400, 10).unwrap();
        db.add_jail("sshd").unwrap();
        let mut extra = BanTimeExtra::new();
        extra.set_opt("increment", Some("true")).unwrap();

        let ip = TicketId::parse("192.0.2.42");
        let mut prior = Ticket::new(ip.clone(), 1000.0);
        prior.ban_count = 3;
        prior.ban_time = Some(600);
        db.add_ban("sshd", &prior, 600).unwrap();

        // New failure after prior ban boosts retry by 4 (total 5 with base 1).
        let mut next_fail = Ticket::new(ip.clone(), 2000.0);
        assert_eq!(
            failure_found_boost(&extra, Some(&db), "sshd", &mut next_fail, 5),
            4
        );
        // Old/restored line at or before last ban time gets no boost.
        let mut old_fail = Ticket::new(ip.clone(), 1000.0);
        assert_eq!(
            failure_found_boost(&extra, Some(&db), "sshd", &mut old_fail, 5),
            0
        );

        let mut new_ban = Ticket::new(ip, 2000.0);
        let escalated = incr_ban_time(&extra, Some(&db), "sshd", 10, &mut new_ban);
        assert_eq!(escalated, 10 * (1 << 3));
        assert_eq!(new_ban.ban_count, 4);
        assert_eq!(new_ban.ban_time, Some(80));
        assert!(!new_ban.restored);

        // overalljails=false (bool or string) must not pull ban history from other jails.
        extra
            .set_opt_value("overalljails", &PickleValue::Bool(false))
            .unwrap();
        assert_eq!(
            extra.get_opt("overalljails"),
            Some(PickleValue::Bool(false))
        );
        let mut other_jail_ban = Ticket::new(TicketId::parse("192.0.2.42"), 2000.0);
        assert_eq!(
            incr_ban_time(&extra, Some(&db), "nginx", 10, &mut other_jail_ban),
            10
        );
        extra.set_opt("overalljails", Some("false")).unwrap();
        assert_eq!(
            extra.get_opt("overalljails"),
            Some(PickleValue::Str("false".to_owned()))
        );
        assert!(!extra.overall_jails());
        extra.set_opt("overalljails", Some("true")).unwrap();
        assert!(extra.overall_jails());
        let mut cross_jail_ban = Ticket::new(TicketId::parse("192.0.2.42"), 2000.0);
        assert_eq!(
            incr_ban_time(&extra, Some(&db), "nginx", 10, &mut cross_jail_ban),
            80
        );
    }
}
