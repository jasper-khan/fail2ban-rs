//! Fail2Ban 1.1.1 client response beautifier (`fail2ban/client/beautifier.py`).

use std::fmt::Write as _;

use crate::logging::{LogLevel, log_msg};
use crate::protocol::PickleValue;

/// ASCII box-drawing glyphs for `stats` (`encUtf = 0`).
const CHAR_TABLE_ASCII: [&str; 8] = ["|", "-", "|", "x", "x", "-", "|", "-"];
/// UTF-8 box-drawing glyphs for `stats` (`encUtf = 1`).
const CHAR_TABLE_UTF8: [&str; 8] = ["║", "═", "╟", "╫", "╬", "╩", "│", "─"];

/// Stateful response formatter matching upstream `fail2ban.client.beautifier.Beautifier`.
#[derive(Debug, Clone)]
pub struct Beautifier {
    input_cmd: Vec<String>,
    enc_utf: bool,
}

impl Default for Beautifier {
    fn default() -> Self {
        Self::new()
    }
}

impl Beautifier {
    pub fn new() -> Self {
        Self {
            input_cmd: Vec::new(),
            enc_utf: detect_utf8_stdout(),
        }
    }

    pub fn with_cmd(cmd: Vec<String>) -> Self {
        Self {
            input_cmd: cmd,
            enc_utf: detect_utf8_stdout(),
        }
    }

    pub fn set_input_cmd(&mut self, cmd: Vec<String>) {
        self.input_cmd = cmd;
    }

    pub fn input_cmd(&self) -> &[String] {
        &self.input_cmd
    }

    pub fn set_utf8(&mut self, utf8: bool) {
        self.enc_utf = utf8;
    }

    pub fn beautify(&self, response: &PickleValue) -> String {
        beautify_inner(&self.input_cmd, response, self.enc_utf)
    }

    pub fn beautify_error(&self, err_kind: &str, err_msg: &str) -> String {
        beautify_error(&self.input_cmd, err_kind, err_msg)
    }
}

/// Format a successful server `PickleValue` response for `cmd` (exact Fail2Ban 1.1.1 parity).
pub fn beautify(cmd: &[String], response: &PickleValue) -> String {
    beautify_inner(cmd, response, detect_utf8_stdout())
}

/// Format an error response `(1, Exception(err_kind, err_msg))` matching upstream `beautifyError`.
pub fn beautify_error(_cmd: &[String], err_kind: &str, err_msg: &str) -> String {
    match err_kind {
        "UnknownJailException" => {
            if err_msg.starts_with("Sorry but the jail '") && err_msg.ends_with("' does not exist")
            {
                err_msg.to_owned()
            } else {
                format!("Sorry but the jail '{err_msg}' does not exist")
            }
        }
        "IndexError" => "Sorry but the command is invalid".to_owned(),
        "DuplicateJailException" => {
            if err_msg.starts_with("The jail '") && err_msg.ends_with("' already exists") {
                err_msg.to_owned()
            } else {
                format!("The jail '{err_msg}' already exists")
            }
        }
        _ => err_msg.to_owned(),
    }
}

fn detect_utf8_stdout() -> bool {
    for var in ["LC_ALL", "LC_CTYPE", "LANG"] {
        if let Ok(val) = std::env::var(var)
            && !val.is_empty()
        {
            let lower = val.to_ascii_lowercase();
            return lower.contains("utf-8") || lower.contains("utf8");
        }
    }
    true
}

fn beautify_inner(cmd: &[String], response: &PickleValue, enc_utf: bool) -> String {
    let Some(head) = cmd.first().map(String::as_str) else {
        return py_str(response);
    };

    match head {
        "ping" => format!("Server replied: {}", py_str(response)),
        "version" => py_str(response),
        "start" => "Jail started".to_owned(),
        "stop" => {
            if matches!(response, PickleValue::None) {
                if cmd.len() == 1 {
                    "Shutdown successful".to_owned()
                } else {
                    "Jail stopped".to_owned()
                }
            } else {
                py_str(response)
            }
        }
        "add" => format!("Added jail {}", py_str(response)),
        "flushlogs" => format!("logs: {}", py_str(response)),
        "echo" => match response.as_list() {
            Some(items) => items.iter().map(py_str).collect::<Vec<_>>().join(" "),
            None => py_str(response),
        },
        "status" => format_status(cmd, response).unwrap_or_else(|| {
            log_beautifier_fallback(cmd, response);
            py_str(response)
        }),
        "stats" | "statistics" | "statistic" => {
            format_stats(response, enc_utf).unwrap_or_else(|| {
                log_beautifier_fallback(cmd, response);
                py_str(response)
            })
        }
        _ => beautify_subcommand(cmd, response),
    }
}

fn beautify_subcommand(cmd: &[String], response: &PickleValue) -> String {
    let Some(arg1) = cmd.get(1).map(String::as_str) else {
        return py_str(response);
    };
    match arg1 {
        "syslogsocket" => format!("Current syslog socket is:\n`- {}", py_str(response)),
        "logtarget" => format!("Current logging target is:\n`- {}", py_str(response)),
        "loglevel" => {
            let repr_val = match response {
                PickleValue::Int(n) => py_repr_str(level_name_from_int(*n)),
                other => py_repr(other),
            };
            format!("Current logging level is {repr_val}")
        }
        "dbfile" => {
            if matches!(response, PickleValue::None) {
                "Database currently disabled".to_owned()
            } else {
                format!("Current database file is:\n`- {}", py_str(response))
            }
        }
        "dbpurgeage" => {
            if matches!(response, PickleValue::None) {
                "Database currently disabled".to_owned()
            } else {
                format!(
                    "Current database purge age is:\n`- {}seconds",
                    py_str(response)
                )
            }
        }
        _ => beautify_jail_subcommand(cmd, response),
    }
}

fn beautify_jail_subcommand(cmd: &[String], response: &PickleValue) -> String {
    let Some(arg2) = cmd.get(2).map(String::as_str) else {
        return py_str(response);
    };
    match arg2 {
        "logpath" | "addlogpath" | "dellogpath" => {
            let Some(items) = response.as_list() else {
                log_beautifier_fallback(cmd, response);
                return py_str(response);
            };
            format_tree_list(
                items,
                "No file is currently monitored",
                "Current monitored log file(s):",
            )
        }
        "logencoding" => format!("Current log encoding is set to:\n{}", py_str(response)),
        "journalmatch" | "addjournalmatch" | "deljournalmatch" => {
            let Some(items) = response.as_list() else {
                log_beautifier_fallback(cmd, response);
                return py_str(response);
            };
            if items.is_empty() {
                "No journal match filter set".to_owned()
            } else {
                let joined = items
                    .iter()
                    .map(|entry| match entry.as_list() {
                        Some(parts) => parts.iter().map(py_str).collect::<Vec<_>>().join(" "),
                        None => py_str(entry),
                    })
                    .collect::<Vec<_>>()
                    .join(" + ");
                format!("Current match filter:\n{joined}")
            }
        }
        "datepattern" => {
            let prefix = "Current date pattern set to: ";
            match response {
                PickleValue::None => format!("{prefix}Not set/required"),
                _ => match response.as_list() {
                    Some([first, second, ..]) => {
                        if matches!(first, PickleValue::None) {
                            format!("{prefix}{}", py_str(second))
                        } else {
                            format!("{prefix}{} ({})", py_str(first), py_str(second))
                        }
                    }
                    _ => {
                        log_beautifier_fallback(cmd, response);
                        py_str(response)
                    }
                },
            }
        }
        "ignoreip" | "addignoreip" | "delignoreip" => {
            let Some(items) = response.as_list() else {
                log_beautifier_fallback(cmd, response);
                return py_str(response);
            };
            format_tree_list(
                items,
                "No IP address/network is ignored",
                "These IP addresses/networks are ignored:",
            )
        }
        "failregex" | "addfailregex" | "delfailregex" | "ignoreregex" | "addignoreregex"
        | "delignoreregex" => {
            let Some(items) = response.as_list() else {
                log_beautifier_fallback(cmd, response);
                return py_str(response);
            };
            if items.is_empty() {
                "No regular expression is defined".to_owned()
            } else {
                let mut out = String::from("The following regular expression are defined:\n");
                let last = items.len() - 1;
                for (idx, item) in items.iter().enumerate() {
                    let branch = if idx == last { "`-" } else { "|-" };
                    let _ = write!(out, "{branch} [{idx}]: {}", py_str(item));
                    if idx != last {
                        out.push('\n');
                    }
                }
                out
            }
        }
        "actions" => {
            let jail = cmd.get(1).map(String::as_str).unwrap_or("");
            let Some(items) = response.as_list() else {
                log_beautifier_fallback(cmd, response);
                return py_str(response);
            };
            if items.is_empty() {
                format!("No actions for jail {jail}")
            } else {
                let joined = items.iter().map(py_str).collect::<Vec<_>>().join(", ");
                format!("The jail {jail} has the following actions:\n{joined}")
            }
        }
        "actionproperties" => {
            let jail = cmd.get(1).map(String::as_str).unwrap_or("");
            let action = cmd.get(3).map(String::as_str).unwrap_or("");
            let Some(items) = response.as_list() else {
                log_beautifier_fallback(cmd, response);
                return py_str(response);
            };
            if items.is_empty() {
                format!("No properties for jail {jail} action {action}")
            } else {
                let joined = items.iter().map(py_str).collect::<Vec<_>>().join(", ");
                format!("The jail {jail} action {action} has the following properties:\n{joined}")
            }
        }
        "actionmethods" => {
            let jail = cmd.get(1).map(String::as_str).unwrap_or("");
            let action = cmd.get(3).map(String::as_str).unwrap_or("");
            let Some(items) = response.as_list() else {
                log_beautifier_fallback(cmd, response);
                return py_str(response);
            };
            if items.is_empty() {
                format!("No methods for jail {jail} action {action}")
            } else {
                let joined = items.iter().map(py_str).collect::<Vec<_>>().join(", ");
                format!("The jail {jail} action {action} has the following methods:\n{joined}")
            }
        }
        "banip" if cmd.first().map(String::as_str) == Some("get") => match response.as_list() {
            Some(items) => {
                let sep = match cmd.get(3).map(String::as_str) {
                    None => " ",
                    Some("--with-time") => "\n",
                    Some(s) => s,
                };
                items.iter().map(py_str).collect::<Vec<_>>().join(sep)
            }
            None => py_str(response),
        },
        _ => py_str(response),
    }
}

fn format_tree_list(items: &[PickleValue], empty_msg: &str, header: &str) -> String {
    if items.is_empty() {
        return empty_msg.to_owned();
    }
    let mut out = String::from(header);
    out.push('\n');
    let last = items.len() - 1;
    for (idx, item) in items.iter().enumerate() {
        let branch = if idx == last { "`-" } else { "|-" };
        let _ = write!(out, "{branch} {}", py_str(item));
        if idx != last {
            out.push('\n');
        }
    }
    out
}

fn format_status(cmd: &[String], response: &PickleValue) -> Option<String> {
    let mut lines: Vec<String> = Vec::new();
    if cmd.len() > 1 && cmd[1] != "--all" {
        lines.push(format!("Status for the jail: {}", cmd[1]));
        append_jail_stat(response, "", &mut lines)?;
        return Some(lines.join("\n"));
    }

    let items = response.as_list()?;
    let (head_items, jstat) = if cmd.len() > 1 {
        let last = items.last()?;
        let entries = match last {
            PickleValue::Dict(entries) => entries.as_slice(),
            _ => return None,
        };
        (&items[..items.len() - 1], Some(entries))
    } else {
        (items, None)
    };
    let has_jstat = jstat.is_some_and(|entries| !entries.is_empty());

    lines.push("Status".to_owned());
    for (n, res1) in head_items.iter().enumerate() {
        let pair = res1.as_list()?;
        if pair.len() < 2 {
            return None;
        }
        let prefix1 = if !has_jstat && n + 1 == head_items.len() {
            "`-"
        } else {
            "|-"
        };
        let val = format_status_val(&pair[1]);
        lines.push(format!("{prefix1} {}:\t{val}", py_str(&pair[0])));
    }

    if let Some(entries) = jstat
        && !entries.is_empty()
    {
        lines.push("`- Status for the jails:".to_owned());
        let len = entries.len();
        for (i, (name, j)) in entries.iter().enumerate() {
            let last = i + 1 == len;
            let prefix1 = if last { "`-" } else { "|-" };
            lines.push(format!("   {prefix1} Jail: {}", py_str(name)));
            let sub_pref = if last { "      " } else { "   |  " };
            append_jail_stat(j, sub_pref, &mut lines)?;
        }
    }

    Some(lines.join("\n"))
}

fn append_jail_stat(response: &PickleValue, pref: &str, out: &mut Vec<String>) -> Option<()> {
    let sections = response.as_list()?;
    for (n, res1) in sections.iter().enumerate() {
        let pair1 = res1.as_list()?;
        if pair1.len() < 2 {
            return None;
        }
        let is_last1 = n + 1 == sections.len();
        let prefix1 = if is_last1 { "`-" } else { "|-" };
        out.push(format!("{pref}{prefix1} {}", py_str(&pair1[0])));

        let child_pref = if is_last1 {
            format!("{pref}   ")
        } else {
            format!("{pref}|  ")
        };
        let sub_items = pair1[1].as_list()?;
        for (m, res2) in sub_items.iter().enumerate() {
            let pair2 = res2.as_list()?;
            if pair2.len() < 2 {
                return None;
            }
            let prefix2 = if m + 1 == sub_items.len() { "`-" } else { "|-" };
            let val = format_status_val(&pair2[1]);
            out.push(format!(
                "{child_pref}{prefix2} {}:\t{val}",
                py_str(&pair2[0])
            ));
        }
    }
    Some(())
}

fn format_status_val(val: &PickleValue) -> String {
    match val {
        PickleValue::List(items) => items.iter().map(py_str).collect::<Vec<_>>().join(" "),
        other => py_str(other),
    }
}

fn format_stats(response: &PickleValue, enc_utf: bool) -> Option<String> {
    let entries = match response {
        PickleValue::Dict(entries) => entries,
        _ => return None,
    };
    if entries.is_empty() {
        return Some("No jails found.".to_owned());
    }

    let ct = if enc_utf {
        &CHAR_TABLE_UTF8
    } else {
        &CHAR_TABLE_ASCII
    };

    let mut rows: Vec<[String; 6]> = Vec::with_capacity(entries.len());
    for (jail, val) in entries {
        let parts = val.as_list()?;
        if parts.len() < 3 {
            return None;
        }
        let flt = parts[1].as_list()?;
        let act = parts[2].as_list()?;
        if flt.len() < 2 || act.len() < 2 {
            return None;
        }
        rows.push([
            py_str(jail),
            py_str(&parts[0]),
            py_str(&flt[0]),
            py_str(&flt[1]),
            py_str(&act[0]),
            py_str(&act[1]),
        ]);
    }

    let minlens = [8usize, 8, 3, 3, 3, 3];
    let mut lens = minlens;
    for row in &rows {
        for (i, cell) in row.iter().enumerate() {
            let w = cell.chars().count();
            if w > lens[i] {
                lens[i] = w;
            }
        }
    }

    let tlens = [
        lens[0],
        lens[1],
        3 + lens[2] + lens[3],
        3 + lens[4] + lens[5],
    ];
    let col_sep = format!(" {} ", ct[0]);
    let sub_sep = format!(" {} ", ct[6]);

    let mut out = Vec::with_capacity(rows.len() + 5);

    // Top group headers
    out.push(format!(
        " {:<w0$}{col_sep}{:<w1$}{col_sep}{:<w2$}{col_sep}{:<w3$}",
        "",
        "",
        "Filter",
        "Actions",
        w0 = tlens[0],
        w1 = tlens[1],
        w2 = tlens[2],
        w3 = tlens[3]
    ));

    // Jail | Backend |---x---
    let mid_join = format!("{}{}{}", ct[7], ct[3], ct[7]);
    let top_rule = format!(
        "{}{}{}{}",
        ct[7].repeat(tlens[2]),
        mid_join,
        ct[7].repeat(tlens[3]),
        ct[7]
    );
    out.push(format!(
        " {:<w0$}{col_sep}{:<w1$} {}{}{top_rule}",
        "Jail",
        "Backend",
        ct[2],
        ct[7],
        w0 = tlens[0],
        w1 = tlens[1]
    ));

    // Sub-headers
    out.push(format!(
        " {:<w0$}{col_sep}{:<w1$}{col_sep}{:>w2$}{sub_sep}{:>w3$}{col_sep}{:>w4$}{sub_sep}{:>w5$}",
        "",
        "",
        "cur",
        "tot",
        "cur",
        "tot",
        w0 = lens[0],
        w1 = lens[1],
        w2 = lens[2],
        w3 = lens[3],
        w4 = lens[4],
        w5 = lens[5]
    ));

    // Header/data divider
    let hdr_join = format!("{}{}{}", ct[1], ct[4], ct[1]);
    let hdr_rule = tlens
        .iter()
        .map(|&n| ct[1].repeat(n))
        .collect::<Vec<_>>()
        .join(&hdr_join);
    out.push(format!("{}{hdr_rule}{}", ct[1], ct[1]));

    // Data rows
    for row in &rows {
        out.push(format!(
            " {:<w0$}{col_sep}{:<w1$}{col_sep}{:>w2$}{sub_sep}{:>w3$}{col_sep}{:>w4$}{sub_sep}{:>w5$}",
            row[0],
            row[1],
            row[2],
            row[3],
            row[4],
            row[5],
            w0 = lens[0],
            w1 = lens[1],
            w2 = lens[2],
            w3 = lens[3],
            w4 = lens[4],
            w5 = lens[5]
        ));
    }

    // Bottom border
    let bot_join = format!("{}{}{}", ct[1], ct[5], ct[1]);
    let bot_rule = tlens
        .iter()
        .map(|&n| ct[1].repeat(n))
        .collect::<Vec<_>>()
        .join(&bot_join);
    out.push(format!("{}{bot_rule}{}", ct[1], ct[1]));

    Some(out.join("\n"))
}

fn level_name_from_int(n: i64) -> &'static str {
    match n {
        50 => "CRITICAL",
        40 => "ERROR",
        30 => "WARNING",
        25 => "NOTICE",
        20 => "INFO",
        10 => "DEBUG",
        7 => "TRACEDEBUG",
        5 => "HEAVYDEBUG",
        _ => "NOTSET",
    }
}

fn log_beautifier_fallback(cmd: &[String], response: &PickleValue) {
    log_msg(
        LogLevel::Warning,
        "fail2ban.client.beautifier",
        &format!(
            "Beautify {} with {cmd:?} fell back to raw formatting",
            py_repr(response)
        ),
    );
}

/// Format a `PickleValue` using Python `str(val)` semantics.
pub fn py_str(val: &PickleValue) -> String {
    match val {
        PickleValue::Str(s) => s.clone(),
        PickleValue::Exception { message, .. } => message.clone(),
        other => py_repr(other),
    }
}

/// Format a `PickleValue` using Python `repr(val)` semantics (exact parity for `banned`, `-d`, etc.).
pub fn py_repr(val: &PickleValue) -> String {
    let mut out = String::new();
    write_py_repr(&mut out, val);
    out
}

/// Format a `PickleValue` resembling Python `pprint.pformat(val, width=width, indent=indent)`.
pub fn py_pformat(val: &PickleValue, width: usize, indent: usize) -> String {
    let single = py_repr(val);
    if single.len() <= width {
        return single;
    }
    let mut out = String::new();
    write_py_pformat(&mut out, val, width, indent, 0);
    out
}

fn write_py_pformat(
    out: &mut String,
    val: &PickleValue,
    width: usize,
    indent: usize,
    depth: usize,
) {
    let single = py_repr(val);
    let current_indent = depth * indent;
    if single.len() + current_indent <= width {
        out.push_str(&single);
        return;
    }
    match val {
        PickleValue::List(items) if !items.is_empty() => {
            out.push('[');
            let pad = " ".repeat((depth + 1) * indent);
            for (i, item) in items.iter().enumerate() {
                if i == 0 {
                    out.push(' ');
                } else {
                    out.push_str(",\n");
                    out.push_str(&pad);
                }
                write_py_pformat(out, item, width, indent, depth + 1);
            }
            out.push(']');
        }
        PickleValue::Tuple(items) if !items.is_empty() => {
            out.push('(');
            let pad = " ".repeat((depth + 1) * indent);
            for (i, item) in items.iter().enumerate() {
                if i == 0 {
                    out.push(' ');
                } else {
                    out.push_str(",\n");
                    out.push_str(&pad);
                }
                write_py_pformat(out, item, width, indent, depth + 1);
            }
            if items.len() == 1 {
                out.push(',');
            }
            out.push(')');
        }
        PickleValue::Dict(entries) if !entries.is_empty() => {
            out.push('{');
            let pad = " ".repeat((depth + 1) * indent);
            for (i, (k, v)) in entries.iter().enumerate() {
                if i == 0 {
                    out.push(' ');
                } else {
                    out.push_str(",\n");
                    out.push_str(&pad);
                }
                write_py_repr(out, k);
                out.push_str(": ");
                write_py_pformat(out, v, width, indent, depth + 1);
            }
            out.push('}');
        }
        _ => out.push_str(&single),
    }
}

fn write_py_repr(out: &mut String, val: &PickleValue) {
    match val {
        PickleValue::None => out.push_str("None"),
        PickleValue::Bool(true) => out.push_str("True"),
        PickleValue::Bool(false) => out.push_str("False"),
        PickleValue::Int(n) => {
            let _ = write!(out, "{n}");
        }
        PickleValue::Float(f) => write_py_float(out, *f),
        PickleValue::Str(s) => write_py_str(out, s),
        PickleValue::Bytes(bytes) => {
            out.push('b');
            let lossy = String::from_utf8_lossy(bytes);
            write_py_str(out, &lossy);
        }
        PickleValue::List(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                write_py_repr(out, item);
            }
            out.push(']');
        }
        PickleValue::Tuple(items) => {
            out.push('(');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                write_py_repr(out, item);
            }
            if items.len() == 1 {
                out.push(',');
            }
            out.push(')');
        }
        PickleValue::Dict(entries) => {
            out.push('{');
            for (i, (k, v)) in entries.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                write_py_repr(out, k);
                out.push_str(": ");
                write_py_repr(out, v);
            }
            out.push('}');
        }
        PickleValue::Exception { kind, message } => {
            out.push_str(kind);
            out.push('(');
            write_py_str(out, message);
            out.push(')');
        }
    }
}

fn write_py_float(out: &mut String, f: f64) {
    if f.is_nan() {
        out.push_str("nan");
    } else if f.is_infinite() {
        if f.is_sign_negative() {
            out.push_str("-inf");
        } else {
            out.push_str("inf");
        }
    } else if f == 0.0 {
        if f.is_sign_negative() {
            out.push_str("-0.0");
        } else {
            out.push_str("0.0");
        }
    } else {
        let s = format!("{f}");
        out.push_str(&s);
        if !s.contains('.') && !s.contains('e') && !s.contains('E') {
            out.push_str(".0");
        }
    }
}

fn py_repr_str(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    write_py_str(&mut out, text);
    out
}

fn write_py_str(out: &mut String, text: &str) {
    let quote = if text.contains('\'') && !text.contains('"') {
        '"'
    } else {
        '\''
    };
    out.push(quote);
    for c in text.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            c if c.is_control() => {
                let code = u32::from(c);
                if code <= 0xff {
                    let _ = write!(out, "\\x{code:02x}");
                } else {
                    let _ = write!(out, "\\u{code:04x}");
                }
            }
            c => out.push(c),
        }
    }
    out.push(quote);
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn cmd(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn basic_commands_match_upstream() {
        assert_eq!(
            beautify(&cmd(&["ping"]), &PickleValue::Str("pong".to_owned())),
            "Server replied: pong"
        );
        assert_eq!(
            beautify(&cmd(&["version"]), &PickleValue::Str("1.1.1".to_owned())),
            "1.1.1"
        );
        assert_eq!(
            beautify(&cmd(&["add"]), &PickleValue::Str("ssh".to_owned())),
            "Added jail ssh"
        );
        assert_eq!(
            beautify(&cmd(&["start"]), &PickleValue::None),
            "Jail started"
        );
        assert_eq!(
            beautify(&cmd(&["stop", "ssh"]), &PickleValue::None),
            "Jail stopped"
        );
        assert_eq!(
            beautify(&cmd(&["stop"]), &PickleValue::None),
            "Shutdown successful"
        );
        assert_eq!(
            beautify(
                &cmd(&["flushlogs"]),
                &PickleValue::Str("rolled over".to_owned())
            ),
            "logs: rolled over"
        );
        assert_eq!(
            beautify(
                &cmd(&["flushlogs"]),
                &PickleValue::Str("flushed".to_owned())
            ),
            "logs: flushed"
        );
        assert_eq!(
            beautify(
                &cmd(&["echo", "hi", "there"]),
                &PickleValue::str_list(["hi", "there"])
            ),
            "hi there"
        );
        assert_eq!(
            beautify(&cmd(&["reload"]), &PickleValue::Str("OK".to_owned())),
            "OK"
        );
        assert_eq!(
            beautify(&cmd(&["unban", "1.2.3.4"]), &PickleValue::Int(2)),
            "2"
        );
    }

    #[test]
    fn status_global_jail_and_all_match_upstream() {
        let global = PickleValue::Tuple(vec![
            PickleValue::Tuple(vec![
                PickleValue::Str("Number of jail".to_owned()),
                PickleValue::Int(2),
            ]),
            PickleValue::Tuple(vec![
                PickleValue::Str("Jail list".to_owned()),
                PickleValue::Str("ssh, exim4".to_owned()),
            ]),
        ]);
        assert_eq!(
            beautify(&cmd(&["status"]), &global),
            "Status\n|- Number of jail:\t2\n`- Jail list:\tssh, exim4"
        );

        let ssh_stat = PickleValue::Tuple(vec![
            PickleValue::Tuple(vec![
                PickleValue::Str("Filter".to_owned()),
                PickleValue::List(vec![
                    PickleValue::Tuple(vec![
                        PickleValue::Str("Currently failed".to_owned()),
                        PickleValue::Int(0),
                    ]),
                    PickleValue::Tuple(vec![
                        PickleValue::Str("Total failed".to_owned()),
                        PickleValue::Int(0),
                    ]),
                    PickleValue::Tuple(vec![
                        PickleValue::Str("File list".to_owned()),
                        PickleValue::List(vec![PickleValue::Str("/var/log/auth.log".to_owned())]),
                    ]),
                ]),
            ]),
            PickleValue::Tuple(vec![
                PickleValue::Str("Actions".to_owned()),
                PickleValue::List(vec![
                    PickleValue::Tuple(vec![
                        PickleValue::Str("Currently banned".to_owned()),
                        PickleValue::Int(3),
                    ]),
                    PickleValue::Tuple(vec![
                        PickleValue::Str("Total banned".to_owned()),
                        PickleValue::Int(3),
                    ]),
                    PickleValue::Tuple(vec![
                        PickleValue::Str("Banned IP list".to_owned()),
                        PickleValue::str_list(["192.168.0.1", "10.2.2.1", "2001:db8::1"]),
                    ]),
                ]),
            ]),
        ]);

        assert_eq!(
            beautify(&cmd(&["status", "ssh"]), &ssh_stat),
            concat!(
                "Status for the jail: ssh\n",
                "|- Filter\n",
                "|  |- Currently failed:\t0\n",
                "|  |- Total failed:\t0\n",
                "|  `- File list:\t/var/log/auth.log\n",
                "`- Actions\n",
                "   |- Currently banned:\t3\n",
                "   |- Total banned:\t3\n",
                "   `- Banned IP list:\t192.168.0.1 10.2.2.1 2001:db8::1"
            )
        );

        let exim_stat = PickleValue::Tuple(vec![
            PickleValue::Tuple(vec![
                PickleValue::Str("Filter".to_owned()),
                PickleValue::List(vec![
                    PickleValue::Tuple(vec![
                        PickleValue::Str("Currently failed".to_owned()),
                        PickleValue::Int(3),
                    ]),
                    PickleValue::Tuple(vec![
                        PickleValue::Str("Total failed".to_owned()),
                        PickleValue::Int(6),
                    ]),
                    PickleValue::Tuple(vec![
                        PickleValue::Str("File list".to_owned()),
                        PickleValue::Str("/var/log/exim4/mainlog".to_owned()),
                    ]),
                ]),
            ]),
            PickleValue::Tuple(vec![
                PickleValue::Str("Actions".to_owned()),
                PickleValue::List(vec![
                    PickleValue::Tuple(vec![
                        PickleValue::Str("Currently banned".to_owned()),
                        PickleValue::Int(0),
                    ]),
                    PickleValue::Tuple(vec![
                        PickleValue::Str("Total banned".to_owned()),
                        PickleValue::Int(0),
                    ]),
                    PickleValue::Tuple(vec![
                        PickleValue::Str("Banned IP list".to_owned()),
                        PickleValue::List(Vec::new()),
                    ]),
                ]),
            ]),
        ]);

        let all_resp = PickleValue::Tuple(vec![
            PickleValue::Tuple(vec![
                PickleValue::Str("Number of jail".to_owned()),
                PickleValue::Int(2),
            ]),
            PickleValue::Tuple(vec![
                PickleValue::Str("Jail list".to_owned()),
                PickleValue::Str("ssh, exim4".to_owned()),
            ]),
            PickleValue::Dict(vec![
                (PickleValue::Str("ssh".to_owned()), ssh_stat),
                (PickleValue::Str("exim4".to_owned()), exim_stat),
            ]),
        ]);
        assert_eq!(
            beautify(&cmd(&["status", "--all"]), &all_resp),
            concat!(
                "Status\n",
                "|- Number of jail:\t2\n",
                "|- Jail list:\tssh, exim4\n",
                "`- Status for the jails:\n",
                "   |- Jail: ssh\n",
                "   |  |- Filter\n",
                "   |  |  |- Currently failed:\t0\n",
                "   |  |  |- Total failed:\t0\n",
                "   |  |  `- File list:\t/var/log/auth.log\n",
                "   |  `- Actions\n",
                "   |     |- Currently banned:\t3\n",
                "   |     |- Total banned:\t3\n",
                "   |     `- Banned IP list:\t192.168.0.1 10.2.2.1 2001:db8::1\n",
                "   `- Jail: exim4\n",
                "      |- Filter\n",
                "      |  |- Currently failed:\t3\n",
                "      |  |- Total failed:\t6\n",
                "      |  `- File list:\t/var/log/exim4/mainlog\n",
                "      `- Actions\n",
                "         |- Currently banned:\t0\n",
                "         |- Total banned:\t0\n",
                "         `- Banned IP list:\t"
            )
        );
    }

    #[test]
    fn stats_table_ascii_and_empty() {
        let mut b = Beautifier::with_cmd(cmd(&["stats"]));
        b.set_utf8(false);
        assert_eq!(
            b.beautify(&PickleValue::Dict(Vec::new())),
            "No jails found."
        );

        let resp = PickleValue::Dict(vec![
            (
                PickleValue::Str("ssh".to_owned()),
                PickleValue::List(vec![
                    PickleValue::Str("systemd".to_owned()),
                    PickleValue::Tuple(vec![PickleValue::Int(3), PickleValue::Int(6)]),
                    PickleValue::Tuple(vec![PickleValue::Int(12), PickleValue::Int(24)]),
                ]),
            ),
            (
                PickleValue::Str("exim4".to_owned()),
                PickleValue::List(vec![
                    PickleValue::Str("pyinotify".to_owned()),
                    PickleValue::Tuple(vec![PickleValue::Int(6), PickleValue::Int(12)]),
                    PickleValue::Tuple(vec![PickleValue::Int(20), PickleValue::Int(20)]),
                ]),
            ),
            (
                PickleValue::Str("jail-with-long-name".to_owned()),
                PickleValue::List(vec![
                    PickleValue::Str("polling".to_owned()),
                    PickleValue::Tuple(vec![PickleValue::Int(0), PickleValue::Int(0)]),
                    PickleValue::Tuple(vec![PickleValue::Int(0), PickleValue::Int(0)]),
                ]),
            ),
        ]);
        assert_eq!(
            b.beautify(&resp),
            concat!(
                "                     |           | Filter    | Actions  \n",
                " Jail                | Backend   |-----------x-----------\n",
                "                     |           | cur | tot | cur | tot\n",
                "---------------------x-----------x-----------x-----------\n",
                " ssh                 | systemd   |   3 |   6 |  12 |  24\n",
                " exim4               | pyinotify |   6 |  12 |  20 |  20\n",
                " jail-with-long-name | polling   |   0 |   0 |   0 |   0\n",
                "---------------------------------------------------------"
            )
        );
    }

    #[test]
    fn banned_and_get_set_commands_match_upstream() {
        let banned_resp = PickleValue::List(vec![
            PickleValue::Dict(vec![(
                PickleValue::Str("sshd".to_owned()),
                PickleValue::str_list(["192.0.2.1", "2001:db8::1"]),
            )]),
            PickleValue::Dict(vec![(
                PickleValue::Str("nginx".to_owned()),
                PickleValue::List(Vec::new()),
            )]),
        ]);
        assert_eq!(
            beautify(&cmd(&["banned"]), &banned_resp),
            "[{'sshd': ['192.0.2.1', '2001:db8::1']}, {'nginx': []}]"
        );
        assert_eq!(
            beautify(
                &cmd(&["get", "sshd", "banned", "192.0.2.1"]),
                &PickleValue::Int(1)
            ),
            "1"
        );
        assert_eq!(
            beautify(
                &cmd(&["get", "sshd", "banned", "192.0.2.1", "192.0.2.2"]),
                &PickleValue::List(vec![PickleValue::Int(1), PickleValue::Int(0)])
            ),
            "[1, 0]"
        );

        assert_eq!(
            beautify(
                &cmd(&["get", "loglevel"]),
                &PickleValue::Str("INFO".to_owned())
            ),
            "Current logging level is 'INFO'"
        );
        assert_eq!(
            beautify(&cmd(&["get", "loglevel"]), &PickleValue::Int(20)),
            "Current logging level is 'INFO'"
        );
        assert_eq!(
            beautify(
                &cmd(&["get", "logtarget"]),
                &PickleValue::Str("/var/log/fail2ban.log".to_owned())
            ),
            "Current logging target is:\n`- /var/log/fail2ban.log"
        );
        assert_eq!(
            beautify(
                &cmd(&["get", "syslogsocket"]),
                &PickleValue::Str("auto".to_owned())
            ),
            "Current syslog socket is:\n`- auto"
        );
        assert_eq!(
            beautify(&cmd(&["get", "dbfile"]), &PickleValue::None),
            "Database currently disabled"
        );
        assert_eq!(
            beautify(
                &cmd(&["get", "dbfile"]),
                &PickleValue::Str("/var/lib/fail2ban/fail2ban.sqlite3".to_owned())
            ),
            "Current database file is:\n`- /var/lib/fail2ban/fail2ban.sqlite3"
        );
        assert_eq!(
            beautify(&cmd(&["get", "dbpurgeage"]), &PickleValue::Int(86400)),
            "Current database purge age is:\n`- 86400seconds"
        );
        assert_eq!(
            beautify(&cmd(&["get", "dbmaxmatches"]), &PickleValue::Int(50)),
            "50"
        );
        assert_eq!(
            beautify(
                &cmd(&["get", "sshd", "findtime"]),
                &PickleValue::Float(600.0)
            ),
            "600.0"
        );
        assert_eq!(
            beautify(
                &cmd(&["get", "sshd", "ignoreself"]),
                &PickleValue::Bool(true)
            ),
            "True"
        );
        assert_eq!(
            beautify(
                &cmd(&["get", "sshd", "logpath"]),
                &PickleValue::List(Vec::new())
            ),
            "No file is currently monitored"
        );
        assert_eq!(
            beautify(
                &cmd(&["set", "sshd", "addlogpath", "/var/log/messages"]),
                &PickleValue::str_list(["/var/log/messages", "/var/log/auth.log"])
            ),
            "Current monitored log file(s):\n|- /var/log/messages\n`- /var/log/auth.log"
        );
        assert_eq!(
            beautify(
                &cmd(&["get", "sshd", "datepattern"]),
                &PickleValue::Tuple(vec![
                    PickleValue::None,
                    PickleValue::Str("Default Detectors".to_owned())
                ])
            ),
            "Current date pattern set to: Default Detectors"
        );
        assert_eq!(
            beautify(
                &cmd(&["get", "sshd", "datepattern"]),
                &PickleValue::Tuple(vec![
                    PickleValue::Str("EPOCH".to_owned()),
                    PickleValue::Str("Epoch".to_owned())
                ])
            ),
            "Current date pattern set to: EPOCH (Epoch)"
        );
        assert_eq!(
            beautify(
                &cmd(&["get", "sshd", "failregex"]),
                &PickleValue::str_list(["^$", ".*"])
            ),
            "The following regular expression are defined:\n|- [0]: ^$\n`- [1]: .*"
        );
        assert_eq!(
            beautify(
                &cmd(&["get", "sshd", "journalmatch"]),
                &PickleValue::List(vec![
                    PickleValue::str_list(["_SYSTEMD_UNIT=sshd.service"]),
                    PickleValue::str_list(["_COMM=sshd", "_UID=0"])
                ])
            ),
            "Current match filter:\n_SYSTEMD_UNIT=sshd.service + _COMM=sshd _UID=0"
        );
        assert_eq!(
            beautify(
                &cmd(&["get", "sshd", "actions"]),
                &PickleValue::str_list(["iptables-multiport"])
            ),
            "The jail sshd has the following actions:\niptables-multiport"
        );
        assert_eq!(
            beautify(
                &cmd(&["get", "sshd", "actionproperties", "iptables"]),
                &PickleValue::str_list(["actionban", "actionunban"])
            ),
            "The jail sshd action iptables has the following properties:\nactionban, actionunban"
        );
        assert_eq!(
            beautify(
                &cmd(&["get", "sshd", "actionmethods", "iptables"]),
                &PickleValue::str_list(["ban", "unban"])
            ),
            "The jail sshd action iptables has the following methods:\nban, unban"
        );
        assert_eq!(
            beautify(
                &cmd(&["get", "sshd", "banip", "--with-time"]),
                &PickleValue::str_list([
                    "1.2.3.4 \t2026-01-01 00:00:00 + 600 = 2026-01-01 00:10:00",
                    "5.6.7.8 \t..."
                ])
            ),
            "1.2.3.4 \t2026-01-01 00:00:00 + 600 = 2026-01-01 00:10:00\n5.6.7.8 \t..."
        );
    }

    #[test]
    fn errors_match_upstream() {
        assert_eq!(
            beautify_error(&cmd(&["status", "sshd"]), "UnknownJailException", "sshd"),
            "Sorry but the jail 'sshd' does not exist"
        );
        assert_eq!(
            beautify_error(
                &cmd(&["status", "sshd"]),
                "UnknownJailException",
                "Sorry but the jail 'sshd' does not exist"
            ),
            "Sorry but the jail 'sshd' does not exist"
        );
        assert_eq!(
            beautify_error(&cmd(&["add", "sshd"]), "DuplicateJailException", "sshd"),
            "The jail 'sshd' already exists"
        );
        assert_eq!(
            beautify_error(&cmd(&["get"]), "IndexError", "list index out of range"),
            "Sorry but the command is invalid"
        );
        assert_eq!(
            beautify_error(&cmd(&["bad"]), "Exception", "Invalid command"),
            "Invalid command"
        );
    }
}
