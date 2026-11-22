//! Fail2Ban 1.1.1 IP, DNS, self-IP, and ignore evaluation (`fail2ban/server/ipdns.py`).

use std::collections::{BTreeSet, HashMap, VecDeque};
use std::ffi::{CStr, CString};
use std::fs;
use std::net::{IpAddr, TcpListener, ToSocketAddrs};
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use crate::config::spec;
use crate::duration::{parse_bool, str2seconds};
use crate::error::{Error, Result};
use crate::logging::{LogLevel, get_level, log_msg};
use crate::ticket::{Ticket, TicketId, canonical_ip};

/// Exact IPv4 regex from upstream `fail2ban/server/ipdns.py`.
pub const IP_4_RE: &str = r"(?:\d{1,3}\.){3}\d{1,3}";
/// Exact IPv6 regex from upstream `fail2ban/server/ipdns.py`.
pub const IP_6_RE: &str = r"(?:[0-9a-fA-F]{1,4}::?|:){1,7}(?:[0-9a-fA-F]{1,4}|(?<=:):)";

/// Fail2Ban `usedns` setting controlling hostname resolution in `<HOST>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum UseDns {
    Yes,
    #[default]
    Warn,
    No,
    Raw,
}

impl UseDns {
    /// Parse a `usedns` string, falling back to `No` with an error log on invalid input.
    pub fn parse(raw: &str) -> Self {
        match raw.trim().to_ascii_lowercase().as_str() {
            "yes" | "true" | "1" | "on" => Self::Yes,
            "warn" => Self::Warn,
            "no" | "false" | "0" | "off" => Self::No,
            "raw" => Self::Raw,
            _ => {
                log_msg(
                    LogLevel::Error,
                    "fail2ban.filter",
                    &format!("Incorrect value {raw:?} specified for usedns. Using safe 'no'"),
                );
                Self::No
            }
        }
    }

    pub const fn from_bool(val: bool) -> Self {
        if val { Self::Yes } else { Self::No }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Yes => "yes",
            Self::Warn => "warn",
            Self::No => "no",
            Self::Raw => "raw",
        }
    }
}

/// Global `allowipv6` configuration (`auto` / `yes` / `no`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum AllowIpv6 {
    #[default]
    Auto = 0,
    Yes = 1,
    No = 2,
}

impl AllowIpv6 {
    pub fn parse(raw: &str) -> Result<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "auto" => Ok(Self::Auto),
            "yes" | "true" | "1" | "on" => Ok(Self::Yes),
            "no" | "false" | "0" | "off" => Ok(Self::No),
            _ => Err(Error::config(format!("Invalid allowipv6 value: {raw:?}"))),
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Yes => "yes",
            Self::No => "no",
        }
    }
}

static ALLOW_IPV6_MODE: AtomicU8 = AtomicU8::new(AllowIpv6::Auto as u8);

/// Configure global `allowipv6` behavior (`Auto`, `Yes`, or `No`).
pub fn set_allow_ipv6(mode: AllowIpv6) {
    ALLOW_IPV6_MODE.store(mode as u8, Ordering::Relaxed);
}

/// Parse and set global `allowipv6` from string (`"auto"`, `"yes"`, `"no"`, etc.).
pub fn set_allow_ipv6_str(raw: &str) -> Result<AllowIpv6> {
    let mode = AllowIpv6::parse(raw)?;
    set_allow_ipv6(mode);
    Ok(mode)
}

/// Return current global `allowipv6` mode.
pub fn allow_ipv6_mode() -> AllowIpv6 {
    match ALLOW_IPV6_MODE.load(Ordering::Relaxed) {
        1 => AllowIpv6::Yes,
        2 => AllowIpv6::No,
        _ => AllowIpv6::Auto,
    }
}

/// Whether IPv6 addresses are currently allowed (honoring global `allowipv6` setting).
pub fn allow_ipv6() -> bool {
    match allow_ipv6_mode() {
        AllowIpv6::Yes => true,
        AllowIpv6::No => false,
        AllowIpv6::Auto => {
            static SYSTEM_IPV6: OnceLock<bool> = OnceLock::new();
            *SYSTEM_IPV6.get_or_init(detect_system_ipv6)
        }
    }
}

fn detect_system_ipv6() -> bool {
    if let Ok(raw) = fs::read_to_string("/proc/sys/net/ipv6/conf/all/disable_ipv6")
        && let Ok(val) = raw.trim().parse::<i32>()
    {
        return val == 0;
    }
    if TcpListener::bind("[::]:0").is_ok() {
        return true;
    }
    net_interface_ips()
        .into_iter()
        .any(|ip| matches!(ip, IpAddr::V6(_)))
}

#[derive(Debug, Clone)]
struct CacheEntry<V> {
    val: V,
    expires_at: Instant,
}

#[derive(Debug)]
struct TtlCache<V> {
    max_count: usize,
    max_time: Duration,
    entries: HashMap<String, CacheEntry<V>>,
    order: VecDeque<String>,
}

impl<V: Clone> TtlCache<V> {
    fn new(max_count: usize, max_time_secs: f64) -> Self {
        let secs = if max_time_secs.is_finite() && max_time_secs > 0.0 {
            max_time_secs
        } else {
            0.0
        };
        Self {
            max_count,
            max_time: Duration::from_secs_f64(secs),
            entries: HashMap::new(),
            order: VecDeque::new(),
        }
    }

    fn get(&mut self, key: &str) -> Option<V> {
        let now = Instant::now();
        if let Some(entry) = self.entries.get(key) {
            if entry.expires_at > now {
                return Some(entry.val.clone());
            }
            self.entries.remove(key);
        }
        None
    }

    fn set(&mut self, key: String, val: V) {
        if self.max_count == 0 {
            return;
        }
        let now = Instant::now();
        if self.entries.len() >= self.max_count && !self.entries.contains_key(&key) {
            while let Some(oldest) = self.order.pop_front() {
                if let Some(ev) = self.entries.remove(&oldest)
                    && ev.expires_at > now
                    && self.entries.len() < self.max_count
                {
                    break;
                }
            }
        }
        self.entries.insert(
            key.clone(),
            CacheEntry {
                val,
                expires_at: now + self.max_time,
            },
        );
        self.order.push_back(key);
    }

    fn clear(&mut self) {
        self.entries.clear();
        self.order.clear();
    }
}

fn name_to_ip_cache() -> &'static Mutex<TtlCache<Vec<TicketId>>> {
    static CACHE: OnceLock<Mutex<TtlCache<Vec<TicketId>>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(TtlCache::new(1000, 300.0)))
}

fn ip_to_name_cache() -> &'static Mutex<TtlCache<Option<String>>> {
    static CACHE: OnceLock<Mutex<TtlCache<Option<String>>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(TtlCache::new(1000, 300.0)))
}

fn self_ips_cache() -> &'static Mutex<TtlCache<Vec<IpAddr>>> {
    static CACHE: OnceLock<Mutex<TtlCache<Vec<IpAddr>>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(TtlCache::new(16, 300.0)))
}

/// Clear cached DNS and self-IP lookups (called on reload).
pub fn clear_dns_caches() {
    if let Ok(mut g) = name_to_ip_cache().lock() {
        g.clear();
    }
    if let Ok(mut g) = ip_to_name_cache().lock() {
        g.clear();
    }
    if let Ok(mut g) = self_ips_cache().lock() {
        g.clear();
    }
}

/// Parse an IP address, `[IPv6]`, CIDR subnet (`ip/prefix`), or netmask (`ip/mask`)
/// into a canonical `TicketId`. Returns `None` if `raw` is not a valid IP or subnet.
pub fn parse_ticket_ip_or_net(raw: &str) -> Option<TicketId> {
    let mut s = raw.trim();
    if s.len() > 2 && s.starts_with('[') && s.ends_with(']') {
        s = &s[1..s.len() - 1];
    }
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Some(TicketId::Ip(canonical_ip(ip)));
    }
    let (addr_part, mask_part) = s.split_once('/')?;
    let ip = addr_part.parse::<IpAddr>().ok()?;
    let prefix = if let Ok(p) = mask_part.parse::<u8>() {
        p
    } else {
        let mask_ip = mask_part.parse::<IpAddr>().ok()?;
        mask_to_prefix_len(ip, mask_ip)?
    };
    let max_prefix = match ip {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };
    if prefix > max_prefix {
        return None;
    }
    Some(TicketId::from_ip_cidr(ip, Some(prefix)))
}

/// Construct a `TicketId` from a captured IP string and optional CIDR prefix length,
/// matching upstream `IPAddr(ip, cidr)`.
pub fn parse_ip_with_cidr(raw: &str, cidr: Option<u8>) -> TicketId {
    let trimmed = raw.trim();
    let stripped = if trimmed.len() > 2 && trimmed.starts_with('[') && trimmed.ends_with(']') {
        &trimmed[1..trimmed.len() - 1]
    } else {
        trimmed
    };
    if let Ok(ip) = stripped.parse::<IpAddr>() {
        if let Some(p) = cidr {
            return TicketId::from_ip_cidr(ip, Some(p));
        }
        return TicketId::Ip(canonical_ip(ip));
    }
    TicketId::parse(stripped)
}

fn mask_to_prefix_len(target: IpAddr, mask: IpAddr) -> Option<u8> {
    match (target, mask) {
        (IpAddr::V4(_), IpAddr::V4(m)) => {
            let bits = u32::from(m);
            let inv = !bits;
            if (inv & inv.wrapping_add(1)) == 0 {
                Some(bits.leading_ones() as u8)
            } else {
                None
            }
        }
        (IpAddr::V6(_), IpAddr::V6(m)) => {
            let bits = u128::from(m);
            let inv = !bits;
            if (inv & inv.wrapping_add(1)) == 0 {
                Some(bits.leading_ones() as u8)
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Resolve a text token (IP, CIDR, or DNS hostname) into zero or more `TicketId`s
/// respecting `UseDns` and `allow_ipv6()`.
pub fn text_to_ip(text: &str, use_dns: UseDns) -> Vec<TicketId> {
    if let Some(id) = parse_ticket_ip_or_net(text) {
        return vec![id];
    }
    if use_dns == UseDns::Raw {
        let trimmed = text.trim();
        return if trimmed.is_empty() {
            Vec::new()
        } else {
            vec![TicketId::Raw(trimmed.to_owned())]
        };
    }
    if matches!(use_dns, UseDns::Yes | UseDns::Warn) {
        let resolved = dns_to_ip(text.trim());
        if !resolved.is_empty() && use_dns == UseDns::Warn {
            log_msg(
                LogLevel::Warning,
                "fail2ban.filter",
                &format!("Determined IP using DNS Lookup: {text} = {resolved:?}"),
            );
        }
        return resolved;
    }
    Vec::new()
}

/// Resolve a hostname to IP addresses via `ToSocketAddrs`, respecting `allow_ipv6()` and caching.
pub fn dns_to_ip(host: &str) -> Vec<TicketId> {
    if host.is_empty() {
        return Vec::new();
    }
    let ipv6_ok = allow_ipv6();
    let cache_key = format!("{}:{host}", if ipv6_ok { "6" } else { "4" });
    if let Ok(mut cache) = name_to_ip_cache().lock()
        && let Some(hit) = cache.get(&cache_key)
    {
        return hit;
    }

    let mut set = BTreeSet::new();
    match (host, 0u16).to_socket_addrs() {
        Ok(addrs) => {
            for sa in addrs {
                let ip = canonical_ip(sa.ip());
                if !ipv6_ok && ip.is_ipv6() {
                    continue;
                }
                set.insert(TicketId::Ip(ip));
            }
        }
        Err(err) => {
            log_msg(
                LogLevel::Warning,
                "fail2ban.filter",
                &format!("Unable to find a corresponding IP address for {host}: {err}"),
            );
        }
    }
    let out: Vec<TicketId> = set.into_iter().collect();
    if let Ok(mut cache) = name_to_ip_cache().lock() {
        cache.set(cache_key, out.clone());
    }
    out
}

/// Reverse DNS lookup via `libc::getnameinfo(..., NI_NAMEREQD)` with TTL caching.
pub fn ip_to_name(ip: &IpAddr) -> Option<String> {
    let key = ip.to_string();
    if let Ok(mut cache) = ip_to_name_cache().lock()
        && let Some(hit) = cache.get(&key)
    {
        return hit;
    }

    let name = reverse_lookup_libc(ip);
    if let Ok(mut cache) = ip_to_name_cache().lock() {
        cache.set(key, name.clone());
    }
    name
}

#[allow(unsafe_code)]
fn reverse_lookup_libc(ip: &IpAddr) -> Option<String> {
    let mut host = [0u8; 1025];
    let rc = match ip {
        IpAddr::V4(v4) => {
            // SAFETY: Zero-initialized `sockaddr_in` has valid layout and zeroed padding.
            let mut sa: nix::libc::sockaddr_in = unsafe { std::mem::zeroed() };
            sa.sin_family = nix::libc::AF_INET as nix::libc::sa_family_t;
            sa.sin_addr = nix::libc::in_addr {
                s_addr: u32::from_ne_bytes(v4.octets()),
            };
            // SAFETY: `sa` points to a valid `sockaddr_in` of exact size, and `host` is
            // writable for `host.len()` bytes.
            unsafe {
                nix::libc::getnameinfo(
                    (&raw const sa).cast::<nix::libc::sockaddr>(),
                    std::mem::size_of::<nix::libc::sockaddr_in>() as nix::libc::socklen_t,
                    host.as_mut_ptr().cast::<nix::libc::c_char>(),
                    host.len() as nix::libc::socklen_t,
                    std::ptr::null_mut(),
                    0,
                    nix::libc::NI_NAMEREQD,
                )
            }
        }
        IpAddr::V6(v6) => {
            // SAFETY: Zero-initialized `sockaddr_in6` has valid layout and zeroed padding.
            let mut sa6: nix::libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
            sa6.sin6_family = nix::libc::AF_INET6 as nix::libc::sa_family_t;
            sa6.sin6_addr = nix::libc::in6_addr {
                s6_addr: v6.octets(),
            };
            // SAFETY: `sa6` points to a valid `sockaddr_in6` of exact size, and `host` is
            // writable for `host.len()` bytes.
            unsafe {
                nix::libc::getnameinfo(
                    (&raw const sa6).cast::<nix::libc::sockaddr>(),
                    std::mem::size_of::<nix::libc::sockaddr_in6>() as nix::libc::socklen_t,
                    host.as_mut_ptr().cast::<nix::libc::c_char>(),
                    host.len() as nix::libc::socklen_t,
                    std::ptr::null_mut(),
                    0,
                    nix::libc::NI_NAMEREQD,
                )
            }
        }
    };
    if rc != 0 {
        return None;
    }
    let end = host.iter().position(|&b| b == 0).unwrap_or(host.len());
    let s = String::from_utf8_lossy(&host[..end]).trim().to_owned();
    if s.is_empty() { None } else { Some(s) }
}

fn net_interface_ips() -> Vec<IpAddr> {
    let mut set = BTreeSet::new();
    if let Ok(addrs) = nix::ifaddrs::getifaddrs() {
        for ifa in addrs {
            let Some(storage) = ifa.address else {
                continue;
            };
            if let Some(v4) = storage.as_sockaddr_in() {
                set.insert(IpAddr::V4(v4.ip()));
            } else if let Some(v6) = storage.as_sockaddr_in6() {
                set.insert(canonical_ip(IpAddr::V6(v6.ip())));
            }
        }
    }
    set.into_iter().collect()
}

#[allow(unsafe_code)]
fn system_hostnames() -> (String, String) {
    let mut buf = [0u8; 256];
    let mut short = String::new();
    // SAFETY: `buf` is a writable byte buffer of `buf.len()` bytes for `gethostname`.
    let rc = unsafe {
        nix::libc::gethostname(buf.as_mut_ptr().cast::<nix::libc::c_char>(), buf.len())
    };
    if rc == 0 {
        let len = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
        short = String::from_utf8_lossy(&buf[..len]).trim().to_owned();
    }
    if short.is_empty() {
        for path in ["/proc/sys/kernel/hostname", "/etc/hostname"] {
            if let Ok(contents) = fs::read_to_string(path) {
                let trimmed = contents.trim();
                if !trimmed.is_empty() {
                    short = trimmed.to_owned();
                    break;
                }
            }
        }
    }
    if short.is_empty() {
        short = "localhost".to_owned();
    }

    let fq = query_fqdn(&short);
    (fq, short)
}

#[allow(unsafe_code)]
fn query_fqdn(short: &str) -> String {
    let Ok(c_name) = CString::new(short) else {
        return short.to_owned();
    };
    // SAFETY: Zero-initialized `addrinfo` is valid for `getaddrinfo` hints.
    let mut hints: nix::libc::addrinfo = unsafe { std::mem::zeroed() };
    hints.ai_socktype = nix::libc::SOCK_DGRAM;
    hints.ai_flags = nix::libc::AI_CANONNAME;
    let mut res: *mut nix::libc::addrinfo = std::ptr::null_mut();
    // SAFETY: `c_name` is NUL-terminated, `hints` is initialized, and `res` is freed below.
    let rc = unsafe {
        nix::libc::getaddrinfo(c_name.as_ptr(), std::ptr::null(), &hints, &mut res)
    };
    if rc == 0 && !res.is_null() {
        let pref = format!("{short}.");
        let mut first: Option<String> = None;
        let mut chosen: Option<String> = None;
        let mut cur = res;
        while !cur.is_null() {
            // SAFETY: `cur` is a non-null node in the linked list from `getaddrinfo`.
            let info = unsafe { &*cur };
            if !info.ai_canonname.is_null() {
                // SAFETY: `ai_canonname` is a valid C string when non-null.
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
        // SAFETY: `res` was returned by a successful `getaddrinfo` call and freed once.
        unsafe { nix::libc::freeaddrinfo(res) };
        if let Some(fq) = chosen.or(first) {
            return fq;
        }
    }
    short.to_owned()
}

/// Return all local interface IPs and resolved local hostnames (`DNSUtils.getSelfIPs`).
pub fn get_self_ips() -> Vec<IpAddr> {
    if let Ok(mut cache) = self_ips_cache().lock()
        && let Some(hit) = cache.get("self")
    {
        return hit;
    }

    let mut set: BTreeSet<IpAddr> = net_interface_ips().into_iter().collect();
    let (fq, sh) = system_hostnames();
    for host in ["localhost", sh.as_str(), fq.as_str()] {
        if host.is_empty() {
            continue;
        }
        if let Ok(addrs) = (host, 0u16).to_socket_addrs() {
            for sa in addrs {
                set.insert(canonical_ip(sa.ip()));
            }
        }
    }
    let out: Vec<IpAddr> = set.into_iter().collect();
    if let Ok(mut cache) = self_ips_cache().lock() {
        cache.set("self".to_owned(), out.clone());
    }
    out
}

/// Bounded TTL cache for `ignorecache = key="...", max-count=100, max-time=5m`.
#[derive(Debug)]
pub struct IgnoreCache {
    key_template: String,
    cache: TtlCache<bool>,
    max_time_secs: f64,
}

impl IgnoreCache {
    pub fn new(key_template: String, max_count: usize, max_time_secs: f64) -> Self {
        Self {
            key_template,
            cache: TtlCache::new(max_count, max_time_secs),
            max_time_secs,
        }
    }

    /// Parse `ignorecache` option string (`key="...", max-count=100, max-time=5m`).
    pub fn parse(raw: &str) -> Result<Option<Self>> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Ok(None);
        }
        let wrapped = format!("cache[{trimmed}]");
        let parsed = spec::parse(&wrapped)?;
        let key = parsed
            .parameters
            .get("key")
            .cloned()
            .ok_or_else(|| Error::config("ignorecache requires 'key' parameter"))?;
        let max_count = match parsed.parameters.get("max-count") {
            Some(v) => v
                .trim()
                .parse::<usize>()
                .map_err(|_| Error::config(format!("invalid ignorecache max-count: {v:?}")))?,
            None => 100,
        };
        let max_time = match parsed.parameters.get("max-time") {
            Some(v) => str2seconds(v)?,
            None => 300.0,
        };
        Ok(Some(Self::new(key, max_count, max_time)))
    }

    pub fn key_template(&self) -> &str {
        &self.key_template
    }

    pub fn max_count(&self) -> usize {
        self.cache.max_count
    }

    pub fn max_time(&self) -> f64 {
        self.max_time_secs
    }

    pub fn get(&mut self, key: &str) -> Option<bool> {
        self.cache.get(key)
    }

    pub fn set(&mut self, key: String, ignored: bool) {
        self.cache.set(key, ignored);
    }

    pub fn clear(&mut self) {
        self.cache.clear();
    }
}

#[derive(Debug, Clone)]
struct FileIpList {
    spec: String,
    path: PathBuf,
    entries: Vec<TicketId>,
    last_stat: Option<(i64, u64, u64)>,
    next_check: Instant,
}

impl FileIpList {
    fn from_spec(raw: &str) -> Option<Self> {
        let path_part = strip_file_scheme(raw)?;
        Some(Self {
            spec: raw.to_owned(),
            path: PathBuf::from(path_part),
            entries: Vec::new(),
            last_stat: None,
            next_check: Instant::now(),
        })
    }

    fn contains(&mut self, id: &TicketId) -> bool {
        self.reload_if_needed();
        self.entries.iter().any(|net| match net {
            TicketId::Raw(host) => dns_to_ip(host).iter().any(|r| id.is_in_net(r)),
            other => id.is_in_net(other),
        })
    }

    fn reload_if_needed(&mut self) {
        let now = Instant::now();
        if now < self.next_check {
            return;
        }
        self.next_check = now + Duration::from_secs(1);
        match fs::metadata(&self.path) {
            Ok(meta) => {
                let st = (meta.mtime(), meta.ino(), meta.size());
                if self.last_stat == Some(st) {
                    return;
                }
                if let Ok(content) = fs::read_to_string(&self.path) {
                    self.entries = parse_ignore_file_words(&content);
                    self.last_stat = Some(st);
                }
            }
            Err(err) => {
                self.next_check = now + Duration::from_secs(60);
                log_msg(
                    LogLevel::Warning,
                    "fail2ban.filter",
                    &format!("Retrieving IPs set from {:?} failed: {err}", self.path),
                );
            }
        }
    }
}

fn strip_file_scheme(raw: &str) -> Option<&str> {
    let rest = raw.strip_prefix("file:")?;
    if let Some(after) = rest.strip_prefix("//") {
        return Some(after);
    }
    Some(rest)
}

fn parse_ignore_file_words(content: &str) -> Vec<TicketId> {
    let mut out = Vec::new();
    for line in content.lines() {
        let stripped = match line.find(['#', ';']) {
            Some(idx) => &line[..idx],
            None => line,
        };
        for word in stripped.split(|c: char| c.is_whitespace() || c == ',') {
            let w = word.trim();
            if w.is_empty() {
                continue;
            }
            out.push(parse_ticket_ip_or_net(w).unwrap_or_else(|| TicketId::Raw(w.to_owned())));
        }
    }
    out
}

/// Complete ignore configuration (`ignoreself`, `ignoreip`, `ignorecommand`, `ignorecache`).
#[derive(Debug)]
pub struct IgnoreConfig {
    pub ignore_self: bool,
    pub ignore_ips: Vec<String>,
    pub ignore_nets: Vec<TicketId>,
    pub ignore_command: Option<String>,
    pub ignore_cache: Option<IgnoreCache>,
    ignore_files: Vec<FileIpList>,
}

impl Default for IgnoreConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl IgnoreConfig {
    pub fn new() -> Self {
        Self {
            ignore_self: true,
            ignore_ips: Vec::new(),
            ignore_nets: Vec::new(),
            ignore_command: None,
            ignore_cache: None,
            ignore_files: Vec::new(),
        }
    }

    pub fn set_ignore_self_str(&mut self, raw: &str) -> Result<bool> {
        let b = parse_bool(raw)?;
        self.ignore_self = b;
        Ok(b)
    }

    /// Add an IP, CIDR subnet, DNS hostname, or `file:/path` ignore entry.
    pub fn add_ignore_ip(&mut self, raw: &str) {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return;
        }
        if let Some(file_list) = FileIpList::from_spec(trimmed) {
            if !self.ignore_files.iter().any(|f| f.spec == file_list.spec) {
                self.ignore_ips.push(trimmed.to_owned());
                self.ignore_files.push(file_list);
            }
            return;
        }
        let parsed =
            parse_ticket_ip_or_net(trimmed).unwrap_or_else(|| TicketId::Raw(trimmed.to_owned()));
        if self.ignore_nets.contains(&parsed) {
            return;
        }
        self.ignore_ips.push(trimmed.to_owned());
        self.ignore_nets.push(parsed);
    }

    /// Remove a specific entry (or clear all entries when `None`).
    pub fn del_ignore_ip(&mut self, raw: Option<&str>) -> bool {
        let Some(target) = raw.map(str::trim) else {
            self.ignore_ips.clear();
            self.ignore_nets.clear();
            self.ignore_files.clear();
            return true;
        };
        if let Some(pos) = self.ignore_files.iter().position(|f| f.spec == target) {
            self.ignore_files.remove(pos);
            self.ignore_ips.retain(|s| s != target);
            return true;
        }
        let parsed =
            parse_ticket_ip_or_net(target).unwrap_or_else(|| TicketId::Raw(target.to_owned()));
        if let Some(pos) = self.ignore_nets.iter().position(|n| n == &parsed) {
            self.ignore_nets.remove(pos);
            if let Some(ipos) = self.ignore_ips.iter().position(|s| s == target) {
                self.ignore_ips.remove(ipos);
            }
            return true;
        }
        false
    }

    /// Check whether `id` (and optional `ticket`) is ignored under `ignoreself`,
    /// `ignoreip`, or `ignorecommand` (with `ignorecache` memoization).
    pub fn is_ignored(&mut self, id: &TicketId, ticket: Option<&Ticket>, jail_name: &str) -> bool {
        let target_ip = ticket.map_or(id, Ticket::target_ip);
        let cache_key = self
            .ignore_cache
            .as_ref()
            .map(|c| expand_ignore_tags(c.key_template(), id, target_ip, ticket, jail_name, false));
        if let (Some(cache), Some(k)) = (self.ignore_cache.as_mut(), cache_key.as_ref())
            && let Some(cached) = cache.get(k)
        {
            return cached;
        }

        let mut ignored = false;
        let mut source = "";

        if self.ignore_self
            && let Some(ip) = target_ip.ip()
            && get_self_ips().contains(&canonical_ip(ip))
        {
            ignored = true;
            source = "ignoreself rule";
        }

        if !ignored {
            for net in &self.ignore_nets {
                let matched = match net {
                    TicketId::Raw(host) => dns_to_ip(host)
                        .iter()
                        .any(|resolved| target_ip.is_in_net(resolved)),
                    other => target_ip.is_in_net(other),
                };
                if matched {
                    ignored = true;
                    source = "ip";
                    break;
                }
            }
        }

        if !ignored {
            for fl in &mut self.ignore_files {
                if fl.contains(target_ip) {
                    ignored = true;
                    source = "file";
                    break;
                }
            }
        }

        if !ignored
            && let Some(cmd_tmpl) = self.ignore_command.as_deref()
            && !cmd_tmpl.trim().is_empty()
        {
            let cmd = expand_ignore_tags(cmd_tmpl, id, target_ip, ticket, jail_name, true);
            if get_level() <= LogLevel::Debug {
                log_msg(
                    LogLevel::Debug,
                    "fail2ban.filter",
                    &format!("ignore command: {cmd}"),
                );
            }
            if run_ignore_command(&cmd) {
                ignored = true;
                source = "command";
            }
        }

        if ignored {
            log_msg(
                LogLevel::Info,
                "fail2ban.filter",
                &format!("[{jail_name}] Ignore {target_ip} by {source}"),
            );
        }

        if let (Some(cache), Some(k)) = (self.ignore_cache.as_mut(), cache_key) {
            cache.set(k, ignored);
        }

        ignored
    }
}

fn run_ignore_command(cmd: &str) -> bool {
    match Command::new("sh").arg("-c").arg(cmd).status() {
        Ok(status) => matches!(status.code(), Some(0)),
        Err(err) => {
            log_msg(
                LogLevel::Error,
                "fail2ban.filter",
                &format!("Failed to execute ignorecommand {cmd:?}: {err}"),
            );
            false
        }
    }
}

fn expand_ignore_tags(
    template: &str,
    fid: &TicketId,
    target_ip: &TicketId,
    ticket: Option<&Ticket>,
    jail_name: &str,
    escape_shell: bool,
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
                let Some(name) = template.get(open + 1..index).filter(|s| !s.is_empty()) else {
                    continue;
                };
                if let Some(repl) = resolve_ignore_tag(
                    name,
                    fid,
                    target_ip,
                    ticket,
                    jail_name,
                    escape_shell,
                    &mut cached_ip_host,
                ) {
                    if let Some(lit) = template.get(literal_start..open) {
                        out.push_str(lit);
                    }
                    out.push_str(&repl);
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

fn resolve_ignore_tag(
    name: &str,
    fid: &TicketId,
    target_ip: &TicketId,
    ticket: Option<&Ticket>,
    jail_name: &str,
    escape_shell: bool,
    cached_ip_host: &mut Option<String>,
) -> Option<String> {
    let maybe_escape = |val: String| -> String {
        if escape_shell {
            escape_shell_tag(&val)
        } else {
            val
        }
    };
    match name {
        "ip" | "IP" => Some(maybe_escape(target_ip.to_string())),
        "fid" => Some(maybe_escape(fid.to_string())),
        "ip-rev" => Some(target_ip.ip_rev()),
        "ip-host" => {
            if let Some(cached) = cached_ip_host.as_ref() {
                return Some(maybe_escape(cached.clone()));
            }
            let resolved = target_ip
                .ip()
                .and_then(|ip| ip_to_name(&ip))
                .unwrap_or_else(|| target_ip.to_string());
            *cached_ip_host = Some(resolved.clone());
            Some(maybe_escape(resolved))
        }
        "family" => Some(target_ip.family().to_owned()),
        "name" | "jail.name" => Some(maybe_escape(jail_name.to_owned())),
        "failures" => Some(ticket.map_or(1, |t| t.attempts).to_string()),
        "matches" => {
            let joined = ticket.map(|t| t.matches.join("\n")).unwrap_or_default();
            Some(maybe_escape(joined))
        }
        "time" => Some(ticket.map_or(0.0, |t| t.time).to_string()),
        "subnet" => Some(match target_ip {
            TicketId::Ip(IpAddr::V4(v4)) => format!("{v4}/32"),
            TicketId::Ip(IpAddr::V6(v6)) => format!("{v6}/128"),
            TicketId::Net(net) => net.to_string(),
            TicketId::Raw(s) => maybe_escape(s.clone()),
        }),
        "cidr" => Some(target_ip.prefix_len().map_or_else(String::new, |p| p.to_string())),
        "mask" => Some(target_ip.netmask()),
        "fq-hostname" => Some(system_hostnames().0),
        "sh-hostname" => Some(system_hostnames().1),
        "br" => Some("\n".to_owned()),
        "sp" => Some(" ".to_owned()),
        _ => {
            let suffix = name.strip_prefix("F-")?;
            let data = ticket.map(|t| &t.data)?;
            let lower = suffix.to_ascii_lowercase();
            let mapped = match lower.as_str() {
                "id" => "fid",
                "port" => "fport",
                other => other,
            };
            let val = data
                .get(mapped)
                .or_else(|| data.get(lower.as_str()))
                .or_else(|| {
                    data.iter()
                        .find(|(k, _)| k.eq_ignore_ascii_case(mapped) || k.eq_ignore_ascii_case(&lower))
                        .map(|(_, v)| v)
                })
                .cloned()
                .unwrap_or_default();
            Some(maybe_escape(val))
        }
    }
}

fn escape_shell_tag(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\n' => out.push_str(r"\n"),
            '\r' => out.push_str(r"\r"),
            '\\' | '#' | '&' | ';' | '`' | '|' | '*' | '?' | '~' | '<' | '>' | '^' | '('
            | ')' | '[' | ']' | '{' | '}' | '$' | '\'' | '"' => {
                out.push('\\');
                out.push(ch);
            }
            _ => out.push(ch),
        }
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn usedns_and_allow_ipv6_parsing() {
        assert_eq!(UseDns::parse("yes"), UseDns::Yes);
        assert_eq!(UseDns::parse("WARN"), UseDns::Warn);
        assert_eq!(UseDns::parse("no"), UseDns::No);
        assert_eq!(UseDns::parse("raw"), UseDns::Raw);
        assert_eq!(UseDns::parse("bogus"), UseDns::No);

        let prev = allow_ipv6_mode();
        set_allow_ipv6(AllowIpv6::No);
        assert!(!allow_ipv6());
        set_allow_ipv6(AllowIpv6::Yes);
        assert!(allow_ipv6());
        set_allow_ipv6(prev);
    }

    #[test]
    fn parses_ips_subnets_netmasks_and_raw() {
        assert_eq!(
            text_to_ip("192.0.2.10", UseDns::No),
            vec![TicketId::parse("192.0.2.10")]
        );
        assert_eq!(
            text_to_ip("[2001:db8::1]", UseDns::No),
            vec![TicketId::parse("2001:db8::1")]
        );
        assert_eq!(
            text_to_ip("::ffff:192.0.2.5", UseDns::No),
            vec![TicketId::parse("192.0.2.5")]
        );
        assert_eq!(
            text_to_ip("192.0.2.5/255.255.255.0", UseDns::No),
            vec![TicketId::parse("192.0.2.0/24")]
        );
        assert_eq!(
            text_to_ip("alice", UseDns::Raw),
            vec![TicketId::Raw("alice".to_owned())]
        );
        assert!(text_to_ip("nonexistent.invalid", UseDns::No).is_empty());
    }

    #[test]
    fn ignore_config_checks_subnets_self_and_command_with_cache() {
        let mut cfg = IgnoreConfig::new();
        cfg.ignore_self = false;
        cfg.add_ignore_ip("192.0.2.0/24");
        cfg.add_ignore_ip("2001:db8::/32");

        assert!(cfg.is_ignored(&TicketId::parse("192.0.2.55"), None, "sshd"));
        assert!(cfg.is_ignored(&TicketId::parse("2001:db8::9"), None, "sshd"));
        assert!(!cfg.is_ignored(&TicketId::parse("198.51.100.1"), None, "sshd"));

        cfg.ignore_cache = IgnoreCache::parse(r#"key="<F-USER>@<ip>", max-count=10, max-time=5m"#).unwrap();
        cfg.ignore_command =
            Some(r#"if [ "<F-USER>" = "trusted" ] && [ "<jail.name>" = "sshd" ]; then exit 0; fi; exit 1"#.to_owned());

        let mut t_trusted = Ticket::new(TicketId::parse("198.51.100.1"), 100.0);
        t_trusted.data.insert("user".into(), "trusted".into());
        assert!(cfg.is_ignored(&t_trusted.fid, Some(&t_trusted), "sshd"));

        let mut t_other = Ticket::new(TicketId::parse("198.51.100.1"), 100.0);
        t_other.data.insert("user".into(), "mallory".into());
        assert!(!cfg.is_ignored(&t_other.fid, Some(&t_other), "sshd"));

        // Verify shell injection characters in <F-USER> are escaped rather than evaluated.
        let mut t_inj = Ticket::new(TicketId::parse("198.51.100.1"), 100.0);
        t_inj.data.insert("user".into(), "$(exit 0)".into());
        assert!(!cfg.is_ignored(&t_inj.fid, Some(&t_inj), "sshd"));
    }
}
