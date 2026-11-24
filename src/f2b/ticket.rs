//! Fail2Ban 1.1.1 `Ticket` / `FailTicket` / `BanTicket` shared data model.
//!
//! Used across `filter`, `failmanager`, `banmanager`, `observer`, `db`, `action`, and `server`.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ipnet::IpNet;

/// Canonical address/identifier carried by a Fail2Ban ticket.
///
/// Mirrors Fail2Ban 1.1.1 `IPAddr`: can be an IPv4 address, IPv6 address,
/// IPv4/IPv6 CIDR subnet, or an opaque raw string failure-id (`<F-ID>`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum TicketId {
    Ip(IpAddr),
    Net(IpNet),
    Raw(String),
}

impl TicketId {
    /// Parse a string into a canonical `TicketId` (IP / `[IPv6]` / CIDR / dotted-mask -> Raw fallback).
    pub fn parse(raw: &str) -> Self {
        let s = raw.trim();
        crate::filter::ipdns::parse_ticket_ip_or_net(s).unwrap_or_else(|| Self::Raw(s.to_owned()))
    }

    /// Construct from an IP and optional CIDR prefix length, rejecting out-of-range prefixes.
    pub fn try_from_ip_cidr(ip: IpAddr, cidr: Option<u8>) -> Option<Self> {
        match (ip, cidr) {
            (IpAddr::V4(_), Some(p)) if p > 32 => return None,
            (IpAddr::V6(_), Some(p)) if p > 128 => return None,
            _ => {}
        }
        // Handle IPv4-mapped IPv6 with explicit IPv6 CIDR (match upstream IPAddr: only collapse
        // to IPv4 when cidr is None, or remap >=96 cleanly).
        if let (IpAddr::V6(v6), Some(p)) = (ip, cidr) {
            if p == 128 {
                return Some(Self::Ip(canonical_ip(IpAddr::V6(v6))));
            }
            if let Some(v4) = v6.to_ipv4_mapped()
                && p >= 96
            {
                let v4_prefix = p - 96;
                return Self::try_from_ip_cidr(IpAddr::V4(v4), Some(v4_prefix));
            }
            let net = ipnet::Ipv6Net::new(v6, p).ok()?;
            return Some(Self::Net(IpNet::V6(net.trunc())));
        }
        let ip = canonical_ip(ip);
        match (ip, cidr) {
            (IpAddr::V4(v4), Some(p)) if p < 32 => {
                let net = ipnet::Ipv4Net::new(v4, p).ok()?;
                Some(Self::Net(IpNet::V4(net.trunc())))
            }
            (IpAddr::V6(v6), Some(p)) if p < 128 => {
                let net = ipnet::Ipv6Net::new(v6, p).ok()?;
                Some(Self::Net(IpNet::V6(net.trunc())))
            }
            _ => Some(Self::Ip(ip)),
        }
    }

    /// Construct from an IP and optional CIDR prefix length.
    pub fn from_ip_cidr(ip: IpAddr, cidr: Option<u8>) -> Self {
        Self::try_from_ip_cidr(ip, cidr).unwrap_or_else(|| Self::Ip(canonical_ip(ip)))
    }

    pub fn ip(&self) -> Option<IpAddr> {
        match self {
            Self::Ip(ip) => Some(*ip),
            Self::Net(net) => Some(net.network()),
            Self::Raw(_) => None,
        }
    }

    pub fn family(&self) -> &'static str {
        match self {
            Self::Ip(IpAddr::V4(_)) | Self::Net(IpNet::V4(_)) => "inet4",
            Self::Ip(IpAddr::V6(_)) | Self::Net(IpNet::V6(_)) => "inet6",
            Self::Raw(_) => "",
        }
    }

    pub fn is_ipv6(&self) -> bool {
        matches!(self, Self::Ip(IpAddr::V6(_)) | Self::Net(IpNet::V6(_)))
    }

    /// Format `<ip-rev>` matching Fail2Ban 1.1.1 `IPAddr.ip_rev`.
    pub fn ip_rev(&self) -> String {
        match self.ip() {
            Some(IpAddr::V4(v4)) => {
                let [a, b, c, d] = v4.octets();
                format!("{d}.{c}.{b}.{a}.")
            }
            Some(IpAddr::V6(v6)) => {
                use std::fmt::Write;
                let mut out = String::with_capacity(64);
                for byte in v6.octets().iter().rev() {
                    let _ = write!(out, "{:x}.{:x}.", byte & 0x0f, byte >> 4);
                }
                out
            }
            None => String::new(),
        }
    }

    /// Network mask string (`255.255.255.0` or IPv6 mask) if applicable.
    pub fn netmask(&self) -> String {
        match self {
            Self::Ip(IpAddr::V4(_)) => Ipv4Addr::new(255, 255, 255, 255).to_string(),
            Self::Ip(IpAddr::V6(_)) => Ipv6Addr::from(u128::MAX).to_string(),
            Self::Net(net) => net.netmask().to_string(),
            Self::Raw(_) => String::new(),
        }
    }

    /// CIDR prefix length (`32` / `128` / subnet prefix).
    pub fn prefix_len(&self) -> Option<u8> {
        match self {
            Self::Ip(IpAddr::V4(_)) => Some(32),
            Self::Ip(IpAddr::V6(_)) => Some(128),
            Self::Net(net) => Some(net.prefix_len()),
            Self::Raw(_) => None,
        }
    }

    /// Whether `self` is contained in `other` (exact match or CIDR containment).
    pub fn is_in_net(&self, other: &Self) -> bool {
        if self == other {
            return true;
        }
        match (self, other) {
            (Self::Ip(ip), Self::Net(net)) => net.contains(ip),
            (Self::Net(sub), Self::Net(super_net)) => {
                super_net.prefix_len() <= sub.prefix_len() && super_net.contains(&sub.network())
            }
            _ => false,
        }
    }
}

impl std::fmt::Display for TicketId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ip(ip) => write!(f, "{ip}"),
            Self::Net(net) => write!(f, "{net}"),
            Self::Raw(s) => f.write_str(s),
        }
    }
}

/// Convert IPv4-mapped IPv6 (`::ffff:1.2.3.4`) into canonical IPv4, matching Fail2Ban `IPAddr`.
pub fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        v4 => v4,
    }
}

/// Unified ticket structure matching Fail2Ban 1.1.1 `Ticket` / `FailTicket` / `BanTicket`.
#[derive(Debug, Clone, PartialEq)]
pub struct Ticket {
    /// Primary identifier (IP, CIDR subnet, or custom `<F-ID>`).
    pub fid: TicketId,
    /// Optional separate IP when `<F-ID>` differs from `<HOST>`/`<ADDR>`.
    pub ip: Option<TicketId>,
    /// Earliest failure timestamp in the current window (unix seconds).
    pub first_time: f64,
    /// Most recent failure / ban start timestamp (unix seconds).
    pub time: f64,
    /// Rate-adjusted retry count used against `maxretry`.
    pub retry: u64,
    /// Actual recorded failure attempt count (`<failures>`).
    pub attempts: u64,
    /// Matched log lines retained for `<matches>` and SQLite `data`.
    pub matches: Vec<String>,
    /// Named capture groups (`<F-USER>`, `<F-PORT>`, `<F-*>`, etc.) for actions & SQLite `data`.
    pub data: BTreeMap<String, String>,
    /// Effective ban duration in seconds (`None` = use jail default, `Some(-1)` = permanent).
    pub ban_time: Option<i64>,
    /// Cumulative historical ban count for this ticket (`bancount` / `bantime.increment`).
    pub ban_count: u64,
    /// True if restored from SQLite on startup (respected by `norestored`).
    pub restored: bool,
}

impl Ticket {
    pub fn new(fid: TicketId, time: f64) -> Self {
        Self {
            fid,
            ip: None,
            first_time: time,
            time,
            retry: 1,
            attempts: 1,
            matches: Vec::new(),
            data: BTreeMap::new(),
            ban_time: None,
            ban_count: 0,
            restored: false,
        }
    }

    /// Primary IP target for firewall actions (`ip` if separately captured, otherwise `fid`).
    pub fn target_ip(&self) -> &TicketId {
        self.ip.as_ref().unwrap_or(&self.fid)
    }

    /// Effective ban duration given jail default `default_ban_time`.
    pub fn effective_ban_time(&self, default_ban_time: i64) -> i64 {
        self.ban_time.unwrap_or(default_ban_time)
    }

    /// Ban expiry timestamp (`None` if permanent `-1`).
    pub fn end_of_ban(&self, default_ban_time: i64) -> Option<f64> {
        let bt = self.effective_ban_time(default_ban_time);
        if bt < 0 {
            None
        } else {
            Some(self.time + bt as f64)
        }
    }

    /// Serialize `data` + `matches` into Fail2Ban 1.1.1's SQLite JSON format.
    pub fn to_db_json(&self, max_matches: usize) -> Vec<u8> {
        let mut obj = serde_json::Map::new();
        for (k, v) in &self.data {
            obj.insert(k.clone(), serde_json::Value::String(v.clone()));
        }
        if let Some(ref ip) = self.ip
            && ip != &self.fid
        {
            obj.insert("ip".to_owned(), serde_json::Value::String(ip.to_string()));
        }
        if !self.matches.is_empty() && max_matches > 0 {
            let start = self.matches.len().saturating_sub(max_matches);
            let lines: Vec<serde_json::Value> = self.matches[start..]
                .iter()
                .map(|s| serde_json::Value::String(s.clone()))
                .collect();
            obj.insert("matches".to_owned(), serde_json::Value::Array(lines));
        }
        obj.insert(
            "failures".to_owned(),
            serde_json::Value::Number(serde_json::Number::from(self.attempts)),
        );
        serde_json::to_vec(&serde_json::Value::Object(obj)).unwrap_or_else(|_| b"{}".to_vec())
    }

    /// Populate `matches`, `attempts`, custom `data`, and separate target `ip`
    /// (when `<F-ID>` differs from `<HOST>`) from Fail2Ban 1.1.1's SQLite JSON column.
    pub fn apply_db_json(&mut self, raw: &[u8]) {
        let Ok(serde_json::Value::Object(map)) = serde_json::from_slice::<serde_json::Value>(raw)
        else {
            return;
        };
        for (k, v) in map {
            match k.as_str() {
                "matches" => {
                    if let serde_json::Value::Array(arr) = v {
                        self.matches = arr
                            .into_iter()
                            .filter_map(|x| x.as_str().map(str::to_owned))
                            .collect();
                    }
                }
                "failures" => {
                    if let Some(n) = v.as_u64() {
                        self.attempts = n;
                    }
                }
                _ => {
                    if let Some(s) = v.as_str() {
                        self.data.insert(k, s.to_owned());
                    } else if !v.is_null() {
                        self.data.insert(k, v.to_string());
                    }
                }
            }
        }
        if self.ip.is_none() {
            if let Some(ip_str) = self.data.get("ip")
                && let Some(parsed) = crate::filter::ipdns::parse_ticket_ip_or_net(ip_str)
                && parsed != self.fid
            {
                self.ip = Some(parsed);
            } else if matches!(self.fid, TicketId::Raw(_)) {
                let cidr = match self.data.get("cidr").map(String::as_str) {
                    None | Some("") => Some(None),
                    Some(raw_cidr) => raw_cidr.parse::<u8>().ok().map(Some),
                };
                if let Some(cidr_opt) = cidr
                    && let Some(addr_str) = self.data.get("ip4").or_else(|| self.data.get("ip6"))
                    && let Some(parsed) =
                        crate::filter::ipdns::parse_ip_with_cidr(addr_str, cidr_opt)
                {
                    self.ip = Some(parsed);
                }
            }
        }
    }
}

/// Snapshot of dynamic runtime context supplied when executing an action (`Actions.ActionInfo`).
#[derive(Debug, Clone)]
pub struct ActionContext {
    pub jail_name: String,
    pub ticket: Ticket,
    pub default_ban_time: i64,
    /// Total failures for this IP across all jails (`<ipfailures>`), from DB + current.
    pub ip_failures: u64,
    /// Total failures for this IP in this jail (`<ipjailfailures>`), from DB + current.
    pub ip_jail_failures: u64,
    /// Historical + current matched lines across all jails (`<ipmatches>`).
    pub ip_matches: Vec<String>,
    /// Historical + current matched lines in this jail (`<ipjailmatches>`).
    pub ip_jail_matches: Vec<String>,
    /// Live jail counters exposed to Python `ActionInfo` (`jail.banned`, etc.).
    pub jail_stats: ActionJailStats,
}

#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct ActionJailStats {
    pub banned: usize,
    pub banned_total: u64,
    pub found: usize,
    pub found_total: u64,
}
