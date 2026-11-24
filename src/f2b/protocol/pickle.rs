//! Safe data-only Python pickle protocol 2–5 encoder & decoder for Fail2Ban 1.1.1.
//!
//! Supports all value types exchanged by Fail2Ban's `CSocket` / `Transmitter`:
//! `None`, `bool`, `int`, `float`, `str`, `bytes`, `list`, `tuple`, `dict`,
//! and allowlisted exception / `IPAddr` reductions. Arbitrary Python callables
//! are rejected.

use crate::error::{Error, Result};

const MAX_ITEMS: usize = 1_048_576;
const MAX_TOTAL_NODES: usize = MAX_ITEMS;
const MAX_DEPTH: usize = 32;
const PICKLE_BATCH_SIZE: usize = 1000;

#[derive(Debug, Clone, PartialEq)]
pub enum PickleValue {
    None,
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(String),
    Bytes(Vec<u8>),
    List(Vec<PickleValue>),
    Tuple(Vec<PickleValue>),
    Dict(Vec<(PickleValue, PickleValue)>),
    Exception { kind: String, message: String },
}

impl PickleValue {
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::Str(s) => Some(s),
            _ => None,
        }
    }

    pub fn to_string_lossy(&self) -> String {
        match self {
            Self::None => "None".to_owned(),
            Self::Bool(true) => "True".to_owned(),
            Self::Bool(false) => "False".to_owned(),
            Self::Int(n) => n.to_string(),
            Self::Float(f) => format!("{f}"),
            Self::Str(s) => s.clone(),
            Self::Bytes(b) => String::from_utf8_lossy(b).into_owned(),
            Self::List(items) => format!("{items:?}"),
            Self::Tuple(items) => format!("{items:?}"),
            Self::Dict(entries) => format!("{entries:?}"),
            Self::Exception { message, .. } => message.clone(),
        }
    }

    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Self::Int(n) => Some(*n),
            Self::Bool(b) => Some(i64::from(*b)),
            Self::Str(s) => s.trim().parse().ok(),
            _ => None,
        }
    }

    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Self::Float(f) => Some(*f),
            Self::Int(n) => Some(*n as f64),
            Self::Str(s) => s.trim().parse().ok(),
            _ => None,
        }
    }

    pub fn as_list(&self) -> Option<&[PickleValue]> {
        match self {
            Self::List(v) | Self::Tuple(v) => Some(v),
            _ => None,
        }
    }

    pub fn str_list(items: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self::List(items.into_iter().map(|s| Self::Str(s.into())).collect())
    }
}

/// Encode `val` into Python pickle protocol 2 bytes.
pub fn encode_pickle_v2(val: &PickleValue) -> Vec<u8> {
    let mut out = Vec::with_capacity(128);
    out.push(0x80); // PROTO
    out.push(0x02); // version 2
    write_val(&mut out, val);
    out.push(b'.'); // STOP
    out
}

fn write_val(out: &mut Vec<u8>, val: &PickleValue) {
    match val {
        PickleValue::None => out.push(b'N'),
        PickleValue::Bool(true) => out.push(0x88),
        PickleValue::Bool(false) => out.push(0x89),
        PickleValue::Int(n) => {
            if let Ok(u) = u8::try_from(*n) {
                out.push(b'K');
                out.push(u);
            } else if let Ok(u) = u16::try_from(*n) {
                out.push(b'M');
                out.extend_from_slice(&u.to_le_bytes());
            } else if let Ok(i) = i32::try_from(*n) {
                out.push(b'J');
                out.extend_from_slice(&i.to_le_bytes());
            } else {
                let bytes = n.to_le_bytes();
                out.push(0x8a); // LONG1
                out.push(bytes.len() as u8);
                out.extend_from_slice(&bytes);
            }
        }
        PickleValue::Float(f) => {
            out.push(b'G');
            out.extend_from_slice(&f.to_be_bytes());
        }
        PickleValue::Str(s) => {
            let bytes = s.as_bytes();
            out.push(b'X'); // BINUNICODE
            out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
            out.extend_from_slice(bytes);
        }
        PickleValue::Bytes(bytes) => {
            // Protocol 2 encodes raw bytes via builtins.bytes([..]) so Python 3 decodes as bytes.
            out.extend_from_slice(b"cbuiltins\nbytes\n");
            out.push(b']');
            if !bytes.is_empty() {
                out.push(b'(');
                for &b in bytes {
                    out.push(b'K');
                    out.push(b);
                }
                out.push(b'e');
            }
            out.push(0x85); // TUPLE1
            out.push(b'R'); // REDUCE
        }
        PickleValue::List(items) => {
            out.push(b']');
            for chunk in items.chunks(PICKLE_BATCH_SIZE) {
                out.push(b'(');
                for item in chunk {
                    write_val(out, item);
                }
                out.push(b'e');
            }
        }
        PickleValue::Tuple(items) => match items.as_slice() {
            [] => out.push(b')'),
            [a] => {
                write_val(out, a);
                out.push(0x85); // TUPLE1
            }
            [a, b] => {
                write_val(out, a);
                write_val(out, b);
                out.push(0x86); // TUPLE2
            }
            [a, b, c] => {
                write_val(out, a);
                write_val(out, b);
                write_val(out, c);
                out.push(0x87); // TUPLE3
            }
            many => {
                out.push(b'(');
                for item in many {
                    write_val(out, item);
                }
                out.push(b't'); // TUPLE
            }
        },
        PickleValue::Dict(entries) => {
            out.push(b'}');
            for chunk in entries.chunks(PICKLE_BATCH_SIZE) {
                out.push(b'(');
                for (k, v) in chunk {
                    write_val(out, k);
                    write_val(out, v);
                }
                out.push(b'u'); // SETITEMS
            }
        }
        PickleValue::Exception { kind, message } => {
            let (module, cls) = match kind.as_str() {
                "UnknownJailException" => ("fail2ban.exceptions", "UnknownJailException"),
                "DuplicateJailException" => ("fail2ban.exceptions", "DuplicateJailException"),
                "ValueError" => ("builtins", "ValueError"),
                "TypeError" => ("builtins", "TypeError"),
                "RuntimeError" => ("builtins", "RuntimeError"),
                "KeyError" => ("builtins", "KeyError"),
                "FileNotFoundError" => ("builtins", "FileNotFoundError"),
                "PermissionError" => ("builtins", "PermissionError"),
                "IsADirectoryError" => ("builtins", "IsADirectoryError"),
                "OSError" => ("builtins", "OSError"),
                _ => ("builtins", "Exception"),
            };
            out.push(b'c');
            out.extend_from_slice(module.as_bytes());
            out.push(b'\n');
            out.extend_from_slice(cls.as_bytes());
            out.push(b'\n');
            write_val(out, &PickleValue::Str(message.clone()));
            out.push(0x85); // TUPLE1
            out.push(b'R'); // REDUCE
        }
    }
}

#[derive(Debug, Clone)]
struct TrackedVal {
    val: PickleValue,
    nodes: usize,
    depth: usize,
}

impl TrackedVal {
    fn leaf(val: PickleValue) -> Self {
        Self {
            val,
            nodes: 1,
            depth: 0,
        }
    }
}

#[derive(Debug, Clone)]
enum StackEntry {
    Mark,
    Val(TrackedVal),
    Global(String, String),
}

impl StackEntry {
    fn node_cost(&self) -> usize {
        match self {
            Self::Val(tv) => tv.nodes,
            Self::Mark | Self::Global(_, _) => 1,
        }
    }
}

fn charge_nodes(budget: &mut (usize, usize), count: usize) -> Result<()> {
    let next = budget
        .0
        .checked_add(count)
        .ok_or_else(|| Error::protocol("pickle stream exceeds resource limits"))?;
    if next > budget.1 {
        return Err(Error::protocol("pickle stream exceeds resource limits"));
    }
    budget.0 = next;
    Ok(())
}

fn check_tracked_depth(depth: usize) -> Result<()> {
    if depth > MAX_DEPTH {
        return Err(Error::protocol("pickle nesting exceeds maximum depth"));
    }
    Ok(())
}

fn value_metrics(val: &PickleValue, cur_depth: usize) -> Result<(usize, usize)> {
    check_tracked_depth(cur_depth)?;
    match val {
        PickleValue::List(items) | PickleValue::Tuple(items) => {
            let mut nodes = 1usize;
            let mut max_child_depth = 0usize;
            for item in items {
                let (n, d) = value_metrics(item, cur_depth + 1)?;
                nodes = nodes
                    .checked_add(n)
                    .ok_or_else(|| Error::protocol("pickle stream exceeds resource limits"))?;
                if nodes > MAX_TOTAL_NODES {
                    return Err(Error::protocol("pickle stream exceeds resource limits"));
                }
                max_child_depth = max_child_depth.max(d + 1);
            }
            check_tracked_depth(max_child_depth)?;
            Ok((nodes, max_child_depth))
        }
        PickleValue::Dict(entries) => {
            let mut nodes = 1usize;
            let mut max_child_depth = 0usize;
            for (k, v) in entries {
                let (kn, kd) = value_metrics(k, cur_depth + 1)?;
                let (vn, vd) = value_metrics(v, cur_depth + 1)?;
                nodes = nodes
                    .checked_add(kn)
                    .and_then(|x| x.checked_add(vn))
                    .ok_or_else(|| Error::protocol("pickle stream exceeds resource limits"))?;
                if nodes > MAX_TOTAL_NODES {
                    return Err(Error::protocol("pickle stream exceeds resource limits"));
                }
                max_child_depth = max_child_depth.max(kd.max(vd) + 1);
            }
            check_tracked_depth(max_child_depth)?;
            Ok((nodes, max_child_depth))
        }
        _ => Ok((1, 0)),
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn byte(&mut self) -> Result<u8> {
        let b = *self
            .bytes
            .get(self.pos)
            .ok_or_else(|| Error::protocol("truncated pickle stream"))?;
        self.pos += 1;
        Ok(b)
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(len)
            .ok_or_else(|| Error::protocol("pickle length overflow"))?;
        let slice = self
            .bytes
            .get(self.pos..end)
            .ok_or_else(|| Error::protocol("truncated pickle stream"))?;
        self.pos = end;
        Ok(slice)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        self.take(N)?
            .try_into()
            .map_err(|_| Error::protocol("invalid pickle field"))
    }

    fn read_line(&mut self) -> Result<&'a str> {
        let rem = self
            .bytes
            .get(self.pos..)
            .ok_or_else(|| Error::protocol("truncated pickle line"))?;
        let nl = memchr::memchr(b'\n', rem)
            .ok_or_else(|| Error::protocol("unterminated pickle line"))?;
        let line = std::str::from_utf8(&rem[..nl])
            .map_err(|_| Error::protocol("invalid UTF-8 in pickle line"))?;
        self.pos += nl + 1;
        Ok(line.strip_suffix('\r').unwrap_or(line))
    }
}

/// Decode a Python pickle (protocols 0–5, bounded safe data-only subset).
pub fn decode_pickle(bytes: &[u8]) -> Result<PickleValue> {
    if bytes.is_empty() {
        return Err(Error::protocol("empty pickle stream"));
    }
    let mut r = Reader { bytes, pos: 0 };
    let mut stack: Vec<StackEntry> = Vec::new();
    let mut memo: Vec<Option<StackEntry>> = Vec::new();
    let mut ops = 0usize;
    // Bound total decoded nodes relative to payload size so small memo bombs fail in microseconds.
    let mut total_nodes = (
        0usize,
        bytes.len().saturating_mul(64).clamp(4096, MAX_TOTAL_NODES),
    );

    // Optional PROTO header (protocols 2..=5)
    if bytes[0] == 0x80 {
        let _ = r.byte()?;
        let ver = r.byte()?;
        if !(2..=5).contains(&ver) {
            return Err(Error::protocol(format!(
                "unsupported pickle protocol {ver}"
            )));
        }
    }

    while r.pos < bytes.len() {
        ops += 1;
        if ops > MAX_ITEMS * 4 || stack.len() > MAX_ITEMS || memo.len() > MAX_ITEMS {
            return Err(Error::protocol("pickle stream exceeds resource limits"));
        }
        let op = r.byte()?;
        match op {
            0x95 => {
                // FRAME (protocol 4+)
                let len = usize::try_from(u64::from_le_bytes(r.array()?))
                    .map_err(|_| Error::protocol("pickle frame too large"))?;
                if len > bytes.len().saturating_sub(r.pos) {
                    return Err(Error::protocol("truncated pickle frame"));
                }
            }
            b'(' => stack.push(StackEntry::Mark),
            b'N' => {
                charge_nodes(&mut total_nodes, 1)?;
                stack.push(StackEntry::Val(TrackedVal::leaf(PickleValue::None)));
            }
            0x88 => {
                charge_nodes(&mut total_nodes, 1)?;
                stack.push(StackEntry::Val(TrackedVal::leaf(PickleValue::Bool(true))));
            }
            0x89 => {
                charge_nodes(&mut total_nodes, 1)?;
                stack.push(StackEntry::Val(TrackedVal::leaf(PickleValue::Bool(false))));
            }
            b'I' => {
                let line = r.read_line()?;
                charge_nodes(&mut total_nodes, 1)?;
                if line == "01" {
                    stack.push(StackEntry::Val(TrackedVal::leaf(PickleValue::Bool(true))));
                } else if line == "00" {
                    stack.push(StackEntry::Val(TrackedVal::leaf(PickleValue::Bool(false))));
                } else {
                    let n: i64 = line
                        .parse()
                        .map_err(|_| Error::protocol(format!("invalid pickle INT {line:?}")))?;
                    stack.push(StackEntry::Val(TrackedVal::leaf(PickleValue::Int(n))));
                }
            }
            b'K' => {
                let n = i64::from(r.byte()?);
                charge_nodes(&mut total_nodes, 1)?;
                stack.push(StackEntry::Val(TrackedVal::leaf(PickleValue::Int(n))));
            }
            b'M' => {
                let n = i64::from(u16::from_le_bytes(r.array()?));
                charge_nodes(&mut total_nodes, 1)?;
                stack.push(StackEntry::Val(TrackedVal::leaf(PickleValue::Int(n))));
            }
            b'J' => {
                let n = i64::from(i32::from_le_bytes(r.array()?));
                charge_nodes(&mut total_nodes, 1)?;
                stack.push(StackEntry::Val(TrackedVal::leaf(PickleValue::Int(n))));
            }
            0x8a | 0x8b => {
                let len = if op == 0x8a {
                    usize::from(r.byte()?)
                } else {
                    u32::from_le_bytes(r.array()?) as usize
                };
                let raw = r.take(len)?;
                let n = decode_long_le(raw)?;
                charge_nodes(&mut total_nodes, 1)?;
                stack.push(StackEntry::Val(TrackedVal::leaf(PickleValue::Int(n))));
            }
            b'G' => {
                let f = f64::from_be_bytes(r.array()?);
                charge_nodes(&mut total_nodes, 1)?;
                stack.push(StackEntry::Val(TrackedVal::leaf(PickleValue::Float(f))));
            }
            0x8c | b'X' | 0x8d => {
                let len = match op {
                    0x8c => usize::from(r.byte()?),
                    b'X' => u32::from_le_bytes(r.array()?) as usize,
                    _ => usize::try_from(u64::from_le_bytes(r.array()?))
                        .map_err(|_| Error::protocol("pickle string too large"))?,
                };
                let s = std::str::from_utf8(r.take(len)?)
                    .map_err(|_| Error::protocol("invalid UTF-8 in pickle string"))?;
                charge_nodes(&mut total_nodes, 1)?;
                stack.push(StackEntry::Val(TrackedVal::leaf(PickleValue::Str(
                    s.to_owned(),
                ))));
            }
            b'C' | b'B' | 0x8e => {
                let len = match op {
                    b'C' => usize::from(r.byte()?),
                    b'B' => u32::from_le_bytes(r.array()?) as usize,
                    _ => usize::try_from(u64::from_le_bytes(r.array()?))
                        .map_err(|_| Error::protocol("pickle bytes too large"))?,
                };
                let b = r.take(len)?.to_vec();
                charge_nodes(&mut total_nodes, 1)?;
                stack.push(StackEntry::Val(TrackedVal::leaf(PickleValue::Bytes(b))));
            }
            b'U' | b'T' => {
                let len = if op == b'U' {
                    usize::from(r.byte()?)
                } else {
                    u32::from_le_bytes(r.array()?) as usize
                };
                let s = String::from_utf8_lossy(r.take(len)?).into_owned();
                charge_nodes(&mut total_nodes, 1)?;
                stack.push(StackEntry::Val(TrackedVal::leaf(PickleValue::Str(s))));
            }
            b']' => {
                charge_nodes(&mut total_nodes, 1)?;
                stack.push(StackEntry::Val(TrackedVal::leaf(PickleValue::List(
                    Vec::new(),
                ))));
            }
            b')' => {
                charge_nodes(&mut total_nodes, 1)?;
                stack.push(StackEntry::Val(TrackedVal::leaf(PickleValue::Tuple(
                    Vec::new(),
                ))));
            }
            b'}' => {
                charge_nodes(&mut total_nodes, 1)?;
                stack.push(StackEntry::Val(TrackedVal::leaf(PickleValue::Dict(
                    Vec::new(),
                ))));
            }
            b'a' => {
                let item = pop_val(&mut stack)?;
                match stack.last_mut() {
                    Some(StackEntry::Val(TrackedVal {
                        val: PickleValue::List(list),
                        nodes,
                        depth,
                    })) => {
                        let next_depth = (*depth).max(item.depth + 1);
                        check_tracked_depth(next_depth)?;
                        *nodes = nodes.saturating_add(item.nodes);
                        *depth = next_depth;
                        list.push(item.val);
                    }
                    _ => return Err(Error::protocol("pickle APPEND target is not a list")),
                }
            }
            b'e' => {
                let items = pop_to_mark(&mut stack)?;
                match stack.last_mut() {
                    Some(StackEntry::Val(TrackedVal {
                        val: PickleValue::List(list),
                        nodes,
                        depth,
                    })) => {
                        let mut next_depth = *depth;
                        let mut added_nodes = 0usize;
                        for item in &items {
                            next_depth = next_depth.max(item.depth + 1);
                            added_nodes = added_nodes.saturating_add(item.nodes);
                        }
                        check_tracked_depth(next_depth)?;
                        *nodes = nodes.saturating_add(added_nodes);
                        *depth = next_depth;
                        list.extend(items.into_iter().map(|i| i.val));
                    }
                    _ => return Err(Error::protocol("pickle APPENDS target is not a list")),
                }
            }
            b'l' => {
                let items = pop_to_mark(&mut stack)?;
                charge_nodes(&mut total_nodes, 1)?;
                let mut nodes = 1usize;
                let mut depth = 0usize;
                for item in &items {
                    nodes = nodes.saturating_add(item.nodes);
                    depth = depth.max(item.depth + 1);
                }
                check_tracked_depth(depth)?;
                stack.push(StackEntry::Val(TrackedVal {
                    val: PickleValue::List(items.into_iter().map(|i| i.val).collect()),
                    nodes,
                    depth,
                }));
            }
            0x85 => {
                let a = pop_val(&mut stack)?;
                charge_nodes(&mut total_nodes, 1)?;
                let depth = a.depth + 1;
                check_tracked_depth(depth)?;
                stack.push(StackEntry::Val(TrackedVal {
                    val: PickleValue::Tuple(vec![a.val]),
                    nodes: 1usize.saturating_add(a.nodes),
                    depth,
                }));
            }
            0x86 => {
                let b = pop_val(&mut stack)?;
                let a = pop_val(&mut stack)?;
                charge_nodes(&mut total_nodes, 1)?;
                let depth = a.depth.max(b.depth) + 1;
                check_tracked_depth(depth)?;
                stack.push(StackEntry::Val(TrackedVal {
                    val: PickleValue::Tuple(vec![a.val, b.val]),
                    nodes: 1usize.saturating_add(a.nodes).saturating_add(b.nodes),
                    depth,
                }));
            }
            0x87 => {
                let c = pop_val(&mut stack)?;
                let b = pop_val(&mut stack)?;
                let a = pop_val(&mut stack)?;
                charge_nodes(&mut total_nodes, 1)?;
                let depth = a.depth.max(b.depth).max(c.depth) + 1;
                check_tracked_depth(depth)?;
                stack.push(StackEntry::Val(TrackedVal {
                    val: PickleValue::Tuple(vec![a.val, b.val, c.val]),
                    nodes: 1usize
                        .saturating_add(a.nodes)
                        .saturating_add(b.nodes)
                        .saturating_add(c.nodes),
                    depth,
                }));
            }
            b't' => {
                let items = pop_to_mark(&mut stack)?;
                charge_nodes(&mut total_nodes, 1)?;
                let mut nodes = 1usize;
                let mut depth = 0usize;
                for item in &items {
                    nodes = nodes.saturating_add(item.nodes);
                    depth = depth.max(item.depth + 1);
                }
                check_tracked_depth(depth)?;
                stack.push(StackEntry::Val(TrackedVal {
                    val: PickleValue::Tuple(items.into_iter().map(|i| i.val).collect()),
                    nodes,
                    depth,
                }));
            }
            b's' => {
                let v = pop_val(&mut stack)?;
                let k = pop_val(&mut stack)?;
                match stack.last_mut() {
                    Some(StackEntry::Val(TrackedVal {
                        val: PickleValue::Dict(map),
                        nodes,
                        depth,
                    })) => {
                        let next_depth = (*depth).max(k.depth.max(v.depth) + 1);
                        check_tracked_depth(next_depth)?;
                        *nodes = nodes.saturating_add(k.nodes).saturating_add(v.nodes);
                        *depth = next_depth;
                        map.push((k.val, v.val));
                    }
                    _ => return Err(Error::protocol("pickle SETITEM target is not a dict")),
                }
            }
            b'u' => {
                let items = pop_to_mark(&mut stack)?;
                if items.len() % 2 != 0 {
                    return Err(Error::protocol("pickle SETITEMS odd key/value count"));
                }
                match stack.last_mut() {
                    Some(StackEntry::Val(TrackedVal {
                        val: PickleValue::Dict(map),
                        nodes,
                        depth,
                    })) => {
                        let mut next_depth = *depth;
                        let mut added_nodes = 0usize;
                        for item in &items {
                            next_depth = next_depth.max(item.depth + 1);
                            added_nodes = added_nodes.saturating_add(item.nodes);
                        }
                        check_tracked_depth(next_depth)?;
                        *nodes = nodes.saturating_add(added_nodes);
                        *depth = next_depth;
                        let mut it = items.into_iter();
                        while let (Some(k), Some(v)) = (it.next(), it.next()) {
                            map.push((k.val, v.val));
                        }
                    }
                    _ => return Err(Error::protocol("pickle SETITEMS target is not a dict")),
                }
            }
            0x94 | b'q' | b'r' => {
                let idx = match op {
                    0x94 => memo.len(),
                    b'q' => usize::from(r.byte()?),
                    _ => u32::from_le_bytes(r.array()?) as usize,
                };
                if idx >= MAX_ITEMS {
                    return Err(Error::protocol("pickle memo index out of bounds"));
                }
                let cost = stack
                    .last()
                    .ok_or_else(|| Error::protocol("pickle memo on empty stack"))?
                    .node_cost();
                charge_nodes(&mut total_nodes, cost)?;
                let top = stack
                    .last()
                    .cloned()
                    .ok_or_else(|| Error::protocol("pickle memo on empty stack"))?;
                if memo.len() <= idx {
                    memo.resize(idx + 1, None);
                }
                memo[idx] = Some(top);
            }
            b'h' | b'j' => {
                let idx = if op == b'h' {
                    usize::from(r.byte()?)
                } else {
                    u32::from_le_bytes(r.array()?) as usize
                };
                let entry_ref = memo
                    .get(idx)
                    .and_then(|o| o.as_ref())
                    .ok_or_else(|| Error::protocol("pickle invalid memo reference"))?;
                charge_nodes(&mut total_nodes, entry_ref.node_cost())?;
                stack.push(entry_ref.clone());
            }
            b'c' => {
                let module = r.read_line()?.to_owned();
                let name = r.read_line()?.to_owned();
                charge_nodes(&mut total_nodes, 1)?;
                stack.push(StackEntry::Global(module, name));
            }
            0x93 => {
                // STACK_GLOBAL (protocol 4+)
                let name = match pop_val(&mut stack)?.val {
                    PickleValue::Str(s) => s,
                    _ => return Err(Error::protocol("STACK_GLOBAL name must be str")),
                };
                let module = match pop_val(&mut stack)?.val {
                    PickleValue::Str(s) => s,
                    _ => return Err(Error::protocol("STACK_GLOBAL module must be str")),
                };
                charge_nodes(&mut total_nodes, 1)?;
                stack.push(StackEntry::Global(module, name));
            }
            b'R' => {
                let args = pop_val(&mut stack)?.val;
                let func = stack
                    .pop()
                    .ok_or_else(|| Error::protocol("pickle REDUCE missing callable"))?;
                let val = reduce_safe(func, args)?;
                let (nodes, depth) = value_metrics(&val, 0)?;
                charge_nodes(&mut total_nodes, 1)?;
                stack.push(StackEntry::Val(TrackedVal { val, nodes, depth }));
            }
            b'b' => {
                // BUILD (e.g. setting __dict__ on exception or IPAddr)
                let _state = pop_val(&mut stack)?;
                // Keep target object on stack as-is.
            }
            0x81 => {
                // NEWOBJ
                let args = pop_val(&mut stack)?.val;
                let cls = stack
                    .pop()
                    .ok_or_else(|| Error::protocol("pickle NEWOBJ missing class"))?;
                let val = reduce_safe(cls, args)?;
                let (nodes, depth) = value_metrics(&val, 0)?;
                charge_nodes(&mut total_nodes, 1)?;
                stack.push(StackEntry::Val(TrackedVal { val, nodes, depth }));
            }
            0x8f => {
                // EMPTY_SET (represent as List)
                charge_nodes(&mut total_nodes, 1)?;
                stack.push(StackEntry::Val(TrackedVal::leaf(PickleValue::List(
                    Vec::new(),
                ))));
            }
            0x90 => {
                // ADDITEMS (for sets)
                let items = pop_to_mark(&mut stack)?;
                match stack.last_mut() {
                    Some(StackEntry::Val(TrackedVal {
                        val: PickleValue::List(list),
                        nodes,
                        depth,
                    })) => {
                        let mut next_depth = *depth;
                        let mut added_nodes = 0usize;
                        for item in &items {
                            next_depth = next_depth.max(item.depth + 1);
                            added_nodes = added_nodes.saturating_add(item.nodes);
                        }
                        check_tracked_depth(next_depth)?;
                        *nodes = nodes.saturating_add(added_nodes);
                        *depth = next_depth;
                        list.extend(items.into_iter().map(|i| i.val));
                    }
                    _ => return Err(Error::protocol("pickle ADDITEMS target invalid")),
                }
            }
            b'.' => {
                let tv = match stack.pop() {
                    Some(StackEntry::Val(v)) if stack.is_empty() => v,
                    _ => {
                        return Err(Error::protocol(
                            "pickle did not terminate with single value",
                        ));
                    }
                };
                check_depth(&tv.val, 0)?;
                return Ok(tv.val);
            }
            other => {
                return Err(Error::protocol(format!(
                    "unsupported pickle opcode 0x{other:02x}"
                )));
            }
        }
    }
    Err(Error::protocol("unterminated pickle stream"))
}

fn check_depth(val: &PickleValue, depth: usize) -> Result<()> {
    if depth > MAX_DEPTH {
        return Err(Error::protocol("pickle nesting exceeds maximum depth"));
    }
    match val {
        PickleValue::List(items) | PickleValue::Tuple(items) => {
            for item in items {
                check_depth(item, depth + 1)?;
            }
        }
        PickleValue::Dict(entries) => {
            for (k, v) in entries {
                check_depth(k, depth + 1)?;
                check_depth(v, depth + 1)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn pop_val(stack: &mut Vec<StackEntry>) -> Result<TrackedVal> {
    match stack.pop() {
        Some(StackEntry::Val(v)) => Ok(v),
        _ => Err(Error::protocol("expected value on pickle stack")),
    }
}

fn pop_to_mark(stack: &mut Vec<StackEntry>) -> Result<Vec<TrackedVal>> {
    let idx = stack
        .iter()
        .rposition(|e| matches!(e, StackEntry::Mark))
        .ok_or_else(|| Error::protocol("pickle MARK not found"))?;
    let mut vals = Vec::with_capacity(stack.len() - idx - 1);
    for entry in stack.drain(idx + 1..) {
        match entry {
            StackEntry::Val(v) => vals.push(v),
            _ => return Err(Error::protocol("non-value item inside pickle group")),
        }
    }
    stack.pop(); // remove Mark
    Ok(vals)
}

fn decode_long_le(raw: &[u8]) -> Result<i64> {
    if raw.is_empty() {
        return Ok(0);
    }
    if raw.len() > 8 {
        return Err(Error::protocol("pickle integer exceeds i64 range"));
    }
    let sign_byte = if (raw[raw.len() - 1] & 0x80) != 0 {
        0xff
    } else {
        0x00
    };
    let mut buf = [sign_byte; 8];
    buf[..raw.len()].copy_from_slice(raw);
    Ok(i64::from_le_bytes(buf))
}

/// Allowlisted safe reductions used by Fail2Ban's pickle wire protocol.
fn reduce_safe(callable: StackEntry, args: PickleValue) -> Result<PickleValue> {
    let StackEntry::Global(module, name) = callable else {
        return Err(Error::protocol("pickle REDUCE callable must be global"));
    };
    let arg_list = match args {
        PickleValue::Tuple(v) | PickleValue::List(v) => v,
        other => vec![other],
    };

    // Allowlisted exception types (from fail2ban or builtins)
    if module == "builtins"
        || module == "exceptions"
        || module == "fail2ban.exceptions"
        || name.ends_with("Error")
        || name.ends_with("Exception")
    {
        if module == "builtins" && name == "set" {
            let items = arg_list
                .into_iter()
                .next()
                .and_then(|v| match v {
                    PickleValue::List(l) | PickleValue::Tuple(l) => Some(l),
                    _ => None,
                })
                .unwrap_or_default();
            return Ok(PickleValue::List(items));
        }
        if module == "builtins" && name == "bytes" {
            let bytes = arg_list
                .into_iter()
                .next()
                .and_then(|v| match v {
                    PickleValue::List(l) => Some(
                        l.into_iter()
                            .filter_map(|x| x.as_i64().and_then(|n| u8::try_from(n).ok()))
                            .collect(),
                    ),
                    _ => None,
                })
                .unwrap_or_default();
            return Ok(PickleValue::Bytes(bytes));
        }
        let message = arg_list
            .iter()
            .map(PickleValue::to_string_lossy)
            .collect::<Vec<_>>()
            .join(", ");
        return Ok(PickleValue::Exception {
            kind: name,
            message,
        });
    }

    // Upstream IPAddr(ip, cidr) serialized over socket (e.g. status / banned lists)
    if module == "fail2ban.server.ipdns" && name == "IPAddr" {
        let ip = arg_list
            .first()
            .map(PickleValue::to_string_lossy)
            .unwrap_or_default();
        if let Some(PickleValue::Int(cidr)) = arg_list.get(1)
            && let Ok(prefix) = u8::try_from(*cidr)
        {
            if let Ok(parsed) = ip.parse::<std::net::IpAddr>()
                && let Some(tid) = crate::ticket::TicketId::try_from_ip_cidr(parsed, Some(prefix))
            {
                return Ok(PickleValue::Str(tid.to_string()));
            }
            return Ok(PickleValue::Str(format!("{ip}/{prefix}")));
        }
        return Ok(PickleValue::Str(ip));
    }

    // Upstream collections.OrderedDict
    if module == "collections" && name == "OrderedDict" {
        let entries = arg_list
            .into_iter()
            .next()
            .and_then(|v| match v {
                PickleValue::List(items) => {
                    let mut out = Vec::new();
                    for item in items {
                        if let PickleValue::Tuple(mut pair) | PickleValue::List(mut pair) = item
                            && pair.len() == 2
                        {
                            let val = pair.pop().unwrap_or(PickleValue::None);
                            let key = pair.pop().unwrap_or(PickleValue::None);
                            out.push((key, val));
                        }
                    }
                    Some(out)
                }
                _ => None,
            })
            .unwrap_or_default();
        return Ok(PickleValue::Dict(entries));
    }

    Err(Error::protocol(format!(
        "disallowed pickle global {module}.{name}"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_nested_values() {
        let val = PickleValue::Tuple(vec![
            PickleValue::Int(0),
            PickleValue::List(vec![
                PickleValue::Tuple(vec![
                    PickleValue::Str("Filter".to_owned()),
                    PickleValue::List(vec![
                        PickleValue::Tuple(vec![
                            PickleValue::Str("Currently failed".to_owned()),
                            PickleValue::Int(3),
                        ]),
                        PickleValue::Tuple(vec![
                            PickleValue::Str("File list".to_owned()),
                            PickleValue::List(vec![PickleValue::Str(
                                "/var/log/auth.log".to_owned(),
                            )]),
                        ]),
                    ]),
                ]),
                PickleValue::Bool(true),
                PickleValue::None,
                PickleValue::Float(1.5),
            ]),
        ]);
        let enc = encode_pickle_v2(&val);
        let dec = decode_pickle(&enc).ok();
        assert_eq!(dec, Some(val));
    }

    #[test]
    fn round_trip_exception() {
        let err = PickleValue::Tuple(vec![
            PickleValue::Int(1),
            PickleValue::Exception {
                kind: "UnknownJailException".to_owned(),
                message: "sshd".to_owned(),
            },
        ]);
        let enc = encode_pickle_v2(&err);
        let dec = decode_pickle(&enc).ok();
        assert_eq!(dec, Some(err));
    }
}
