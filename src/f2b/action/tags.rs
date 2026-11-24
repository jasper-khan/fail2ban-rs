//! Fail2Ban 1.1.1 static & dynamic `CommandAction` tag expansion and escaping.
//!
//! Static tags (`replaceTag`) expand recursively within action properties
//! using `crate::config::tags`, resolving `?family=` conditionals and `<br>` / `<sp>`.
//! Dynamic tags (`replaceDynamicTags`) expand in a single non-recursive pass
//! with shell-injection escaping (`escape_tag`) on untrusted log inputs.

use std::collections::BTreeMap;
use std::ffi::{CStr, CString};
use std::net::IpAddr;
use std::sync::OnceLock;

use crate::config::tags as config_tags;
use crate::error::{Error, Result};
use crate::ticket::{ActionContext, TicketId};

use super::policy::Family;

/// Expanded static text, still containing any unresolved runtime tags.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticTemplate(String);

impl StaticTemplate {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }
}

/// Expand static property tags in `query` for the given `family`, mirroring `CommandAction.replaceTag`.
pub fn expand(
    query: &str,
    properties: &BTreeMap<String, String>,
    family: Family,
) -> Result<StaticTemplate> {
    if !query.contains('<') {
        return Ok(StaticTemplate(query.to_owned()));
    }

    let mut resolved = BTreeMap::new();
    for (key, value) in properties {
        if is_runtime_property(key) {
            continue;
        }
        let mut self_reference = false;
        let result = config_tags::expand(value, |tag| {
            if is_runtime_tag(tag) {
                return None;
            }
            if tag == key {
                self_reference = true;
                return None;
            }
            static_value(properties, tag, family).cloned()
        });
        if self_reference {
            return Err(Error::config(format!(
                "recursive CommandAction property {key:?}"
            )));
        }
        let expanded = result
            .map_err(|err| Error::config(format!("CommandAction property {key:?}: {err}")))?;
        resolved.insert(key.clone(), expanded);
    }

    config_tags::expand(query, |tag| {
        if is_runtime_tag(tag) {
            return None;
        }
        static_value(&resolved, tag, family)
            .map(String::as_str)
            .or(match tag {
                "br" => Some("\n"),
                "sp" => Some(" "),
                _ => None,
            })
            .map(str::to_owned)
    })
    .map(StaticTemplate)
    .map_err(|err| Error::config(format!("CommandAction static query: {err}")))
}

fn static_value<'a>(
    properties: &'a BTreeMap<String, String>,
    name: &str,
    family: Family,
) -> Option<&'a String> {
    let conditional = match family {
        Family::Common => None,
        Family::Ipv4 | Family::Ipv6 => {
            properties.get(&format!("{name}?family={}", family.as_str()))
        }
    };
    conditional.or_else(|| properties.get(name))
}

fn is_runtime_tag(tag: &str) -> bool {
    matches!(tag, "matches" | "ipmatches" | "ipjailmatches")
}

fn is_runtime_property(key: &str) -> bool {
    is_runtime_tag(key.split_once("?family=").map_or(key, |(base, _)| base))
}

/// Escape characters that may be used for shell command injection.
///
/// Mirrors `CommandAction.ESCAPE_CRE = r"""[\\#&;`|*?~<>^()\[\]{}$'"\n\r]"""`:
/// `\n` becomes `\n`, `\r` becomes `\r`, and all other characters in the set
/// are prefixed with `\`.
pub fn escape_tag(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\n' => out.push_str(r"\n"),
            '\r' => out.push_str(r"\r"),
            '\\' | '#' | '&' | ';' | '`' | '|' | '*' | '?' | '~' | '<' | '>' | '^' | '(' | ')'
            | '[' | ']' | '{' | '}' | '$' | '\'' | '"' => {
                out.push('\\');
                out.push(ch);
            }
            _ => out.push(ch),
        }
    }
    out
}

/// Cached `(fq-hostname, sh-hostname)` resolved via `gethostname` + `getaddrinfo(AI_CANONNAME)`
/// with `/proc/sys/kernel/hostname` and `/etc/hostname` fallbacks.
pub fn system_hostnames() -> &'static (String, String) {
    static HOSTNAMES: OnceLock<(String, String)> = OnceLock::new();
    HOSTNAMES.get_or_init(|| {
        let sh = query_short_hostname();
        let fq = query_fqdn(&sh);
        (fq, sh)
    })
}

#[allow(unsafe_code)]
fn query_short_hostname() -> String {
    let mut buf = [0u8; 256];
    // SAFETY: `buf` is a valid mutable byte array of length `buf.len()`, and
    // `gethostname` writes at most `buf.len()` bytes.
    let rc =
        unsafe { nix::libc::gethostname(buf.as_mut_ptr().cast::<nix::libc::c_char>(), buf.len()) };
    if rc == 0 {
        let len = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
        let name = String::from_utf8_lossy(&buf[..len]).trim().to_owned();
        if !name.is_empty() {
            return name;
        }
    }
    for path in ["/proc/sys/kernel/hostname", "/etc/hostname"] {
        if let Ok(contents) = std::fs::read_to_string(path) {
            let trimmed = contents.trim();
            if !trimmed.is_empty() {
                return trimmed.to_owned();
            }
        }
    }
    "localhost".to_owned()
}

#[allow(unsafe_code)]
fn query_fqdn(short: &str) -> String {
    let Ok(c_name) = CString::new(short) else {
        return short.to_owned();
    };
    // SAFETY: All-zero `libc::addrinfo` is valid for `getaddrinfo` hints.
    let mut hints: nix::libc::addrinfo = unsafe { std::mem::zeroed() };
    hints.ai_socktype = nix::libc::SOCK_DGRAM;
    hints.ai_flags = nix::libc::AI_CANONNAME;
    let mut res: *mut nix::libc::addrinfo = std::ptr::null_mut();
    // SAFETY: `c_name` is a valid NUL-terminated C string, `hints` is initialized,
    // and `res` receives an allocated linked list freed below via `freeaddrinfo`.
    let rc = unsafe { nix::libc::getaddrinfo(c_name.as_ptr(), std::ptr::null(), &hints, &mut res) };
    if rc == 0 && !res.is_null() {
        let pref = format!("{short}.");
        let mut first: Option<String> = None;
        let mut chosen: Option<String> = None;
        let mut cur = res;
        while !cur.is_null() {
            // SAFETY: `cur` is a non-null node in the linked list returned by `getaddrinfo`.
            let info = unsafe { &*cur };
            if !info.ai_canonname.is_null() {
                // SAFETY: `ai_canonname` is a valid NUL-terminated string when non-null.
                let cand = unsafe { CStr::from_ptr(info.ai_canonname) }
                    .to_string_lossy()
                    .trim()
                    .to_owned();
                if !cand.is_empty() {
                    if cand.starts_with(&pref) {
                        chosen = Some(cand);
                        break;
                    }
                    if first.is_none() {
                        first = Some(cand);
                    }
                }
            }
            cur = info.ai_next;
        }
        // SAFETY: `res` came from a successful `getaddrinfo` call and is freed once.
        unsafe { nix::libc::freeaddrinfo(res) };
        if let Some(fq) = chosen.or(first) {
            return fq;
        }
    }
    short.to_owned()
}

/// Default reverse DNS lookup using the shared TTL-cached resolver.
pub fn default_reverse_dns(ip: &IpAddr) -> Option<String> {
    crate::filter::ipdns::ip_to_name(ip)
}

/// Shell script plus out-of-band positional arguments (`sh -c <script> <arg0> ...`),
/// matching Fail2Ban 1.1.1 `Utils.buildShellCmd`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShellCommand {
    pub script: String,
    pub args: Vec<String>,
}

/// Return `true` iff `value` contains any shell metacharacter from `CommandAction.ESCAPE_CRE`,
/// ASCII whitespace (which causes word splitting outside quotes), or a NUL byte, requiring
/// out-of-band positional argument binding.
pub(crate) fn needs_shell_var(value: &str) -> bool {
    value.chars().any(|ch| {
        ch.is_ascii_whitespace()
            || matches!(
                ch,
                '\\' | '#'
                    | '&'
                    | ';'
                    | '`'
                    | '|'
                    | '*'
                    | '?'
                    | '~'
                    | '<'
                    | '>'
                    | '^'
                    | '('
                    | ')'
                    | '['
                    | ']'
                    | '{'
                    | '}'
                    | '$'
                    | '\''
                    | '"'
                    | '\x0b'
                    | '\0'
            )
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QuoteMode {
    Unquoted,
    Single,
    Double,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QuoteContainer {
    Root,
    Subshell { parens: usize },
    Backtick,
}

#[derive(Debug, Clone, Copy)]
struct QuoteFrame {
    container: QuoteContainer,
    mode: QuoteMode,
    escaped: bool,
}

/// Tracks POSIX `sh` quoting context across literal template fragments so substituted
/// variables expand safely inside single quotes, double quotes, and unquoted positions.
struct ShellQuoteState {
    frames: Vec<QuoteFrame>,
}

impl ShellQuoteState {
    fn new() -> Self {
        Self {
            frames: vec![QuoteFrame {
                container: QuoteContainer::Root,
                mode: QuoteMode::Unquoted,
                escaped: false,
            }],
        }
    }

    fn mode(&self) -> QuoteMode {
        self.frames
            .last()
            .map_or(QuoteMode::Unquoted, |frame| frame.mode)
    }

    fn advance(&mut self, lit: &str) {
        let mut chars = lit.chars().peekable();
        while let Some(ch) = chars.next() {
            let has_parent = self.frames.len() > 1;
            let Some(frame) = self.frames.last_mut() else {
                break;
            };
            match frame.mode {
                QuoteMode::Single => {
                    if ch == '\'' {
                        frame.mode = QuoteMode::Unquoted;
                    }
                }
                QuoteMode::Double => {
                    if frame.escaped {
                        frame.escaped = false;
                    } else if ch == '\\' {
                        frame.escaped = true;
                    } else if ch == '"' {
                        frame.mode = QuoteMode::Unquoted;
                    } else if ch == '$' && chars.peek() == Some(&'(') {
                        let _ = chars.next();
                        self.frames.push(QuoteFrame {
                            container: QuoteContainer::Subshell { parens: 0 },
                            mode: QuoteMode::Unquoted,
                            escaped: false,
                        });
                    } else if ch == '`' {
                        self.frames.push(QuoteFrame {
                            container: QuoteContainer::Backtick,
                            mode: QuoteMode::Unquoted,
                            escaped: false,
                        });
                    }
                }
                QuoteMode::Unquoted => {
                    if frame.escaped {
                        frame.escaped = false;
                    } else if ch == '\\' {
                        frame.escaped = true;
                    } else if ch == '\'' {
                        frame.mode = QuoteMode::Single;
                    } else if ch == '"' {
                        frame.mode = QuoteMode::Double;
                    } else if ch == '$' && chars.peek() == Some(&'(') {
                        let _ = chars.next();
                        self.frames.push(QuoteFrame {
                            container: QuoteContainer::Subshell { parens: 0 },
                            mode: QuoteMode::Unquoted,
                            escaped: false,
                        });
                    } else if ch == '(' {
                        if let QuoteContainer::Subshell { parens } = &mut frame.container {
                            *parens += 1;
                        }
                    } else if ch == ')' {
                        match &mut frame.container {
                            QuoteContainer::Subshell { parens } if *parens > 0 => {
                                *parens -= 1;
                            }
                            QuoteContainer::Subshell { .. } if has_parent => {
                                self.frames.pop();
                            }
                            _ => {}
                        }
                    } else if ch == '`' {
                        if matches!(frame.container, QuoteContainer::Backtick) && has_parent {
                            self.frames.pop();
                        } else {
                            self.frames.push(QuoteFrame {
                                container: QuoteContainer::Backtick,
                                mode: QuoteMode::Unquoted,
                                escaped: false,
                            });
                        }
                    }
                }
            }
        }
    }
}

/// Sanitize a Fail2Ban tag name into a valid POSIX shell variable name (`f2bV_<name>`).
fn shell_var_name(tag: &str) -> String {
    let mut name = String::with_capacity(5 + tag.len());
    name.push_str("f2bV_");
    for ch in tag.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' {
            name.push(ch);
        } else {
            name.push('_');
        }
    }
    name
}

/// Bind dynamic tag values that contain shell metacharacters or whitespace into out-of-band
/// positional arguments (`f2bV_<tag>=$0 ... \n<script>`), matching Fail2Ban 1.1.1
/// `CommandAction.replaceDynamicTags` + `Utils.buildShellCmd` while preserving POSIX shell
/// quoting semantics across single-quoted, double-quoted, and unquoted templates.
pub(crate) fn build_shell_command_from_resolver<F>(template: &str, mut resolve: F) -> ShellCommand
where
    F: FnMut(&str) -> Option<(String, bool)>,
{
    if !template.contains('<') {
        return ShellCommand {
            script: template.to_owned(),
            args: Vec::new(),
        };
    }

    let mut body = String::with_capacity(template.len());
    let mut vars: Vec<(String, String)> = Vec::new();
    let mut quote_state = ShellQuoteState::new();
    let mut literal_start = 0usize;
    let mut tag_start: Option<usize> = None;

    for (index, ch) in template.char_indices() {
        match ch {
            '<' => tag_start = Some(index),
            ' ' => tag_start = None,
            '>' => {
                let Some(open) = tag_start.take() else {
                    continue;
                };
                let Some(name) = template
                    .get(open + 1..index)
                    .filter(|part| !part.is_empty())
                else {
                    continue;
                };
                if let Some((raw_value, protect)) = resolve(name) {
                    if let Some(lit) = template.get(literal_start..open) {
                        quote_state.advance(lit);
                        body.push_str(lit);
                    }
                    if protect && needs_shell_var(&raw_value) {
                        // Strip interior NULs so `execve` never fails with EINVAL on untrusted logs.
                        let clean = if raw_value.contains('\0') {
                            raw_value.replace('\0', "")
                        } else {
                            raw_value
                        };
                        let var_base = if let Some(suffix) = name.strip_prefix("F-") {
                            let lower = suffix.to_ascii_lowercase();
                            let mapped = match lower.as_str() {
                                "id" => "fid",
                                "port" => "fport",
                                other => other,
                            };
                            shell_var_name(&format!("F_{mapped}"))
                        } else {
                            shell_var_name(name)
                        };
                        let var_name = if let Some((existing, _)) =
                            vars.iter().find(|(k, v)| k == &var_base && v == &clean)
                        {
                            existing.clone()
                        } else if !vars.iter().any(|(k, _)| k == &var_base) {
                            vars.push((var_base.clone(), clean));
                            var_base
                        } else {
                            let mut n = 2usize;
                            loop {
                                let candidate = format!("{var_base}_{n}");
                                if !vars.iter().any(|(k, _)| k == &candidate) {
                                    vars.push((candidate.clone(), clean));
                                    break candidate;
                                }
                                n += 1;
                            }
                        };
                        match quote_state.mode() {
                            QuoteMode::Unquoted => {
                                body.push_str("\"${");
                                body.push_str(&var_name);
                                body.push_str("}\"");
                            }
                            QuoteMode::Double => {
                                body.push_str("${");
                                body.push_str(&var_name);
                                body.push('}');
                            }
                            QuoteMode::Single => {
                                body.push_str("'\"${");
                                body.push_str(&var_name);
                                body.push_str("}\"'");
                            }
                        }
                    } else {
                        body.push_str(&raw_value);
                    }
                    literal_start = index + 1;
                }
            }
            _ => {}
        }
    }

    if let Some(tail) = template.get(literal_start..) {
        body.push_str(tail);
    }

    if vars.is_empty() {
        return ShellCommand {
            script: body,
            args: Vec::new(),
        };
    }

    let mut header = String::new();
    let mut args = Vec::with_capacity(vars.len());
    for (idx, (var_name, value)) in vars.into_iter().enumerate() {
        use std::fmt::Write;
        if idx < 10 {
            let _ = write!(header, "{var_name}=${idx} ");
        } else {
            let _ = write!(header, "{var_name}=${{{idx}}} ");
        }
        args.push(value);
    }
    header.push('\n');
    header.push_str(&body);
    ShellCommand {
        script: header,
        args,
    }
}

/// Non-recursive single-pass dynamic tag substitution producing a safe [`ShellCommand`]
/// (`CommandAction.replaceDynamicTags` + `Utils.buildShellCmd`).
pub fn build_shell_command(
    template: &str,
    ctx: &ActionContext,
    family: &str,
    extra_hostname: Option<(&str, &str)>,
    reverse_dns_fn: &dyn Fn(&IpAddr) -> Option<String>,
) -> ShellCommand {
    let mut cached_ip_host: Option<String> = None;
    build_shell_command_from_resolver(template, |name| {
        resolve_dynamic_tag_raw(
            name,
            ctx,
            family,
            extra_hostname,
            reverse_dns_fn,
            &mut cached_ip_host,
        )
    })
}

/// Non-recursive single-pass dynamic tag replacement (`CommandAction.replaceDynamicTags`).
///
/// Kept as a string helper for callers that expect inline escaped text; shell execution
/// paths must use [`build_shell_command`] to pass untrusted values out-of-band.
pub fn replace_dynamic_tags(
    template: &str,
    ctx: &ActionContext,
    family: &str,
    extra_hostname: Option<(&str, &str)>,
    reverse_dns_fn: &dyn Fn(&IpAddr) -> Option<String>,
) -> String {
    if !template.contains('<') {
        return template.to_owned();
    }

    let mut out = String::with_capacity(template.len());
    let mut cached_ip_host: Option<String> = None;
    let mut literal_start = 0usize;
    let mut tag_start: Option<usize> = None;

    for (index, ch) in template.char_indices() {
        match ch {
            '<' => tag_start = Some(index),
            ' ' => tag_start = None,
            '>' => {
                let Some(open) = tag_start.take() else {
                    continue;
                };
                let Some(name) = template
                    .get(open + 1..index)
                    .filter(|part| !part.is_empty())
                else {
                    continue;
                };
                if let Some((raw, protect)) = resolve_dynamic_tag_raw(
                    name,
                    ctx,
                    family,
                    extra_hostname,
                    reverse_dns_fn,
                    &mut cached_ip_host,
                ) {
                    if let Some(lit) = template.get(literal_start..open) {
                        out.push_str(lit);
                    }
                    if protect {
                        out.push_str(&escape_tag(&raw));
                    } else {
                        out.push_str(&raw);
                    }
                    literal_start = index + 1;
                }
            }
            _ => {}
        }
    }

    if let Some(tail) = template.get(literal_start..) {
        out.push_str(tail);
    }
    out
}

/// Non-recursive single-pass replacement for `<family>` only (used by `_getOperation`).
pub(crate) fn replace_family_tag(template: &str, family: &str) -> String {
    if family.is_empty() || !template.contains("<family>") {
        return template.to_owned();
    }
    template.replace("<family>", family)
}

/// Resolve a dynamic tag to `(raw_value, protect_in_shell)`.
///
/// Only structural tokens `<br>` and `<sp>` return `protect = false`; every data tag
/// returns `protect = true` so untrusted values are always bound out-of-band in shell execution.
fn resolve_dynamic_tag_raw(
    name: &str,
    ctx: &ActionContext,
    family: &str,
    extra_hostname: Option<(&str, &str)>,
    reverse_dns_fn: &dyn Fn(&IpAddr) -> Option<String>,
    cached_ip_host: &mut Option<String>,
) -> Option<(String, bool)> {
    match name {
        "ip" | "IP" => Some((ctx.ticket.target_ip().to_string(), true)),
        "fid" => Some((ctx.ticket.fid.to_string(), true)),
        "ip-rev" => Some((ctx.ticket.target_ip().ip_rev(), true)),
        "ip-host" => {
            if let Some(cached) = cached_ip_host.as_ref() {
                return Some((cached.clone(), true));
            }
            let target = ctx.ticket.target_ip();
            let resolved = target
                .ip()
                .and_then(|ip| reverse_dns_fn(&ip))
                .unwrap_or_else(|| target.to_string());
            *cached_ip_host = Some(resolved.clone());
            Some((resolved, true))
        }
        "family" => Some((family.to_owned(), true)),
        "name" | "jail.name" => Some((ctx.jail_name.clone(), true)),
        "jail.banned" => Some((ctx.jail_stats.banned.to_string(), true)),
        "jail.banned_total" => Some((ctx.jail_stats.banned_total.to_string(), true)),
        "jail.found" => Some((ctx.jail_stats.found.to_string(), true)),
        "jail.found_total" => Some((ctx.jail_stats.found_total.to_string(), true)),
        "raw-ticket" => Some((format!("{:?}", ctx.ticket), true)),
        "failures" => Some((ctx.ticket.attempts.to_string(), true)),
        "ipfailures" => Some((ctx.ip_failures.to_string(), true)),
        "ipjailfailures" => Some((ctx.ip_jail_failures.to_string(), true)),
        "matches" => Some((ctx.ticket.matches.join("\n"), true)),
        "ipmatches" => Some((ctx.ip_matches.join("\n"), true)),
        "ipjailmatches" => Some((ctx.ip_jail_matches.join("\n"), true)),
        "time" => Some((format_time(ctx.ticket.time), true)),
        "bantime" => Some((
            ctx.ticket
                .effective_ban_time(ctx.default_ban_time)
                .to_string(),
            true,
        )),
        "bancount" => Some((ctx.ticket.ban_count.to_string(), true)),
        "restored" => Some((if ctx.ticket.restored { "1" } else { "0" }.to_owned(), true)),
        "subnet" => Some((format_subnet(ctx.ticket.target_ip()), true)),
        "cidr" => Some((
            ctx.ticket
                .target_ip()
                .prefix_len()
                .map_or_else(String::new, |p| p.to_string()),
            true,
        )),
        "mask" => Some((ctx.ticket.target_ip().netmask(), true)),
        "fq-hostname" => Some((
            extra_hostname
                .map(|(fq, _)| fq)
                .unwrap_or_else(|| system_hostnames().0.as_str())
                .to_owned(),
            true,
        )),
        "sh-hostname" => Some((
            extra_hostname
                .map(|(_, sh)| sh)
                .unwrap_or_else(|| system_hostnames().1.as_str())
                .to_owned(),
            true,
        )),
        "br" => Some(("\n".to_owned(), false)),
        "sp" => Some((" ".to_owned(), false)),
        _ => {
            let suffix = name
                .strip_prefix("F-")
                .filter(|part| is_capture_name(part))?;
            Some((lookup_capture_raw(&ctx.ticket.data, suffix), true))
        }
    }
}

fn is_capture_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || matches!(b, b'-' | b'_'))
}

fn lookup_capture_raw(data: &BTreeMap<String, String>, suffix: &str) -> String {
    let lower = suffix.to_ascii_lowercase();
    let mapped = match lower.as_str() {
        "id" => "fid",
        "port" => "fport",
        other => other,
    };
    let value = data
        .get(mapped)
        .or_else(|| data.get(lower.as_str()))
        .or_else(|| {
            data.iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(mapped) || k.eq_ignore_ascii_case(&lower))
                .map(|(_, v)| v)
        });
    value.cloned().unwrap_or_default()
}

fn format_time(t: f64) -> String {
    if t.is_finite() && t.fract() == 0.0 && t >= (i64::MIN as f64) && t <= (i64::MAX as f64) {
        format!("{}", t as i64)
    } else {
        format!("{t}")
    }
}

fn format_subnet(id: &TicketId) -> String {
    match id {
        TicketId::Ip(ip) => format!("{ip}/{}", if ip.is_ipv4() { 32 } else { 128 }),
        TicketId::Net(net) => net.to_string(),
        TicketId::Raw(_) => String::new(),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::ticket::Ticket;

    fn options(entries: &[(&str, &str)]) -> BTreeMap<String, String> {
        entries
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect()
    }

    #[test]
    fn nested_static_tags_prefer_conditionals_and_keep_unknowns() {
        let properties = options(&[
            ("collection", "alpha"),
            ("collection?family=inet6", "beta"),
            ("title-alpha", "report-a"),
            ("title-beta", "report-b"),
            ("view", "<title-<collection>>"),
        ]);
        for (family, expected) in [
            (Family::Common, "report-a|<missing>"),
            (Family::Ipv4, "report-a|<missing>"),
            (Family::Ipv6, "report-b|<missing>"),
        ] {
            assert_eq!(
                expand("<view>|<missing>", &properties, family)
                    .unwrap()
                    .as_str(),
                expected,
            );
        }
    }

    #[test]
    fn known_empty_family_value_shadows_generic_and_builtin_fallbacks() {
        let properties = options(&[
            ("leaf", "fallback"),
            ("leaf?family=inet4", ""),
            ("sp?family=inet4", ""),
        ]);
        assert_eq!(
            expand("[<leaf>]<sp>done", &properties, Family::Ipv4)
                .unwrap()
                .as_str(),
            "[]done"
        );
        assert_eq!(
            expand("[<leaf>]<sp>done", &properties, Family::Ipv6)
                .unwrap()
                .as_str(),
            "[fallback] done"
        );
    }

    #[test]
    fn escape_tag_escapes_all_upstream_metacharacters() {
        let raw = "\\#&;`|*?~<>^()[]{}$'\"\n\rABC123";
        let escaped = escape_tag(raw);
        assert_eq!(
            escaped,
            "\\\\\\#\\&\\;\\`\\|\\*\\?\\~\\<\\>\\^\\(\\)\\[\\]\\{\\}\\$\\'\\\"\\n\\rABC123"
        );
    }

    #[test]
    fn replace_dynamic_tags_substitutes_all_tags_non_recursively() {
        let mut ticket = Ticket::new(TicketId::parse("192.0.2.10"), 1_700_000_000.0);
        ticket.attempts = 5;
        ticket.matches = vec![
            "line1 $(id) <ip>".to_owned(),
            "line2 'quoted' \"dq\"".to_owned(),
        ];
        ticket.data.insert("user".to_owned(), "root;rm".to_owned());
        ticket.data.insert("fport".to_owned(), "22".to_owned());
        ticket
            .data
            .insert("CUSTOM_KEY".to_owned(), "a&b".to_owned());
        ticket.restored = true;
        ticket.ban_count = 3;

        let ctx = ActionContext {
            jail_name: "sshd".to_owned(),
            ticket,
            default_ban_time: 600,
            ip_failures: 12,
            ip_jail_failures: 7,
            ip_matches: vec!["m1".to_owned(), "m2$x".to_owned()],
            ip_jail_matches: vec!["jm1".to_owned()],
            jail_stats: Default::default(),
        };

        let rdns_calls = std::cell::Cell::new(0usize);
        let tpl = "<ip> <IP> <fid> <ip-rev> <ip-host> <ip-host> <family> <name> \
            <failures> <ipfailures> <ipjailfailures> <time> <bantime> <bancount> <restored> \
            <subnet> <cidr> <mask> <fq-hostname> <sh-hostname><br><sp>\
            [<matches>|<ipmatches>|<ipjailmatches>] \
            [<F-USER>|<F-PORT>|<F-CUSTOM_KEY>|<F-MISSING>|<F-user>|<unknown>]";

        let rendered = replace_dynamic_tags(
            tpl,
            &ctx,
            "inet4",
            Some(("host.example.com", "host")),
            &|_| {
                rdns_calls.set(rdns_calls.get() + 1);
                Some("attacker.example".to_owned())
            },
        );
        assert_eq!(rdns_calls.get(), 1);
        assert_eq!(
            rendered,
            "192.0.2.10 192.0.2.10 192.0.2.10 10.2.0.192. attacker.example attacker.example inet4 sshd \
            5 12 7 1700000000 600 3 1 \
            192.0.2.10/32 32 255.255.255.255 host.example.com host\n \
            [line1 \\$\\(id\\) \\<ip\\>\\nline2 \\'quoted\\' \\\"dq\\\"|m1\\nm2\\$x|jm1] \
            [root\\;rm|22|a\\&b||<F-user>|<unknown>]"
        );

        // `<ip>` inside `<matches>` was escaped and NOT recursively expanded;
        // also verify reverse DNS fallback to `<ip>` and lazy skip when absent.
        let rdns_skipped = std::cell::Cell::new(0usize);
        let simple = replace_dynamic_tags("ban <ip>", &ctx, "inet4", None, &|_| {
            rdns_skipped.set(rdns_skipped.get() + 1);
            None
        });
        assert_eq!(simple, "ban 192.0.2.10");
        assert_eq!(rdns_skipped.get(), 0);

        let fallback = replace_dynamic_tags("<ip-host>", &ctx, "inet4", None, &|_| None);
        assert_eq!(fallback, "192.0.2.10");
    }

    #[test]
    fn replace_dynamic_tags_handles_cidr_and_ipv6_rev() {
        let mut ticket = Ticket::new(TicketId::parse("2001:db8::/32"), 100.5);
        ticket.ip = Some(TicketId::parse("2001:db8::1"));
        let ctx = ActionContext {
            jail_name: "web".to_owned(),
            ticket,
            default_ban_time: -1,
            ip_failures: 1,
            ip_jail_failures: 1,
            ip_matches: vec![],
            ip_jail_matches: vec![],
            jail_stats: Default::default(),
        };
        let rendered = replace_dynamic_tags(
            "<fid>|<ip>|<ip-rev>|<subnet>|<cidr>|<bantime>|<time>|<restored>",
            &ctx,
            "inet6",
            Some(("fq", "sh")),
            &|_| None,
        );
        assert_eq!(
            rendered,
            "2001:db8::/32|2001:db8::1|1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.|2001:db8::1/128|128|-1|100.5|0"
        );
    }

    #[test]
    fn system_hostnames_returns_non_empty() {
        let (fq, sh) = system_hostnames();
        assert!(!fq.is_empty());
        assert!(!sh.is_empty());
    }
}
