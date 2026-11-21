//! Pure stdout rendering for original Fail2Ban 1.1.1 client responses.
//!
//! This models ping, basic/short status, and scoped ban reads without reading
//! live state, processing wire data, or changing the existing fail2ban-rs CLI.

use std::fmt::Write as _;
use std::net::{IpAddr, Ipv4Addr};

use crate::legacy_client::quoted;
pub(crate) use crate::legacy_client_bans::Banned as BannedReply;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StatusFlavor {
    Basic,
    Short,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum StatusSource {
    /// The base filter does not report file or journal provenance.
    None,
    Files(Vec<String>),
    /// Ordered journal token groups, separated by + in the original output.
    JournalMatches(Vec<Vec<String>>),
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct JailStatus {
    pub(crate) name: String,
    pub(crate) currently_failed: u64,
    pub(crate) total_failed: u64,
    pub(crate) source: StatusSource,
    pub(crate) currently_banned: u64,
    pub(crate) total_banned: u64,
    /// Original server display values in its returned order.
    pub(crate) banned_ips: Vec<String>,
}

/// Successful `get JAIL banip` (non-time mode). The query projection has
/// already applied the original end-time ordering.
pub(crate) fn banip(ips: &[IpAddr], separator: Option<&str>) -> String {
    let separator = separator.unwrap_or(" ");
    let mut output = ips
        .iter()
        .copied()
        .map(ip_text)
        .collect::<Vec<_>>()
        .join(separator);
    output.push('\n');
    output
}

/// Successful `banned` or `get JAIL banned`: the client prints the
/// original typed Python list/dict/integer instead of joining its items.
/// Jail identifier strings are from the scoped, synthetic reply snapshot.
pub(crate) fn banned(reply: &BannedReply) -> String {
    let mut output = String::new();
    match reply {
        BannedReply::Jails(jails) => write_list(&mut output, jails, |out, (name, ips)| {
            out.push('{');
            out.push_str(&quoted(name));
            out.push_str(": ");
            write_list(out, ips, |out, ip| out.push_str(&quoted(&ip_text(*ip))));
            out.push('}');
        }),
        BannedReply::ByAddress(rows) => write_list(&mut output, rows, |out, names| {
            write_list(out, names, |out, name| out.push_str(&quoted(name)));
        }),
        BannedReply::Addresses(ips) => {
            write_list(&mut output, ips, |out, ip| {
                out.push_str(&quoted(&ip_text(*ip)));
            });
        }
        BannedReply::Membership(value) => {
            let _ = write!(output, "{value}");
        }
        BannedReply::Memberships(values) => write_list(&mut output, values, |out, value| {
            let _ = write!(out, "{value}");
        }),
    }
    output.push('\n');
    output
}

fn write_list<T>(output: &mut String, items: &[T], mut item: impl FnMut(&mut String, &T)) {
    output.push('[');
    for (i, value) in items.iter().enumerate() {
        if i != 0 {
            output.push_str(", ");
        }
        item(output, value);
    }
    output.push(']');
}

fn ip_text(ip: IpAddr) -> String {
    let canonical = ip.to_canonical();
    if let IpAddr::V6(ipv6) = canonical
        && let [0, 0, 0, 0, 0, 0, high, low] = ipv6.segments()
        && high != 0
    {
        // The original Linux inet_ntop also emits IPv4-compatible IPv6
        // addresses with a dotted tail when the leading zero run is six.
        // Mapped addresses were already reduced to plain IPv4 above.
        let [a, b] = high.to_be_bytes();
        let [c, d] = low.to_be_bytes();
        return format!("::{}", Ipv4Addr::from([a, b, c, d]));
    }
    canonical.to_string()
}

/// A successful ping as printed by the original client, including LF.
pub(crate) fn ping(response: &str) -> String {
    format!("Server replied: {response}\n")
}

/// Generic status. The original server sorts its jail names before rendering.
pub(crate) fn status(jail_names: &[String]) -> String {
    let mut jail_names = jail_names.iter().map(String::as_str).collect::<Vec<_>>();
    jail_names.sort_unstable();
    let mut output = String::new();
    write_status_head(&mut output, &jail_names, false);
    output
}

/// Basic or short status for one requested jail.
pub(crate) fn status_jail(status: &JailStatus, flavor: StatusFlavor) -> String {
    let mut output = format!("Status for the jail: {}\n", status.name);
    write_jail(&mut output, status, flavor, "");
    output
}

/// Expanded generic status with the original ordered per-jail tree.
pub(crate) fn status_all(jails: &[JailStatus], flavor: StatusFlavor) -> String {
    let mut jails = jails.iter().collect::<Vec<_>>();
    jails.sort_unstable_by(|left, right| left.name.cmp(&right.name));
    let names = jails
        .iter()
        .map(|jail| jail.name.as_str())
        .collect::<Vec<_>>();
    let mut output = String::new();
    write_status_head(&mut output, &names, !jails.is_empty());
    if !jails.is_empty() {
        output.push_str("`- Status for the jails:\n");
        for (index, jail) in jails.iter().enumerate() {
            let last = index + 1 == jails.len();
            let branch = branch(last);
            let _ = writeln!(output, "   {branch} Jail: {}", jail.name);
            write_jail(
                &mut output,
                jail,
                flavor,
                if last { "      " } else { "   |  " },
            );
        }
    }
    output
}

pub(crate) fn unknown_jail(name: &str) -> String {
    format!("Sorry but the jail '{name}' does not exist\n")
}

fn branch(last: bool) -> &'static str {
    if last { "`-" } else { "|-" }
}

fn write_status_head(output: &mut String, names: &[&str], has_jails_section: bool) {
    let _ = writeln!(output, "Status\n|- Number of jail:\t{}", names.len());
    let _ = writeln!(
        output,
        "{} Jail list:\t{}",
        branch(!has_jails_section),
        names.join(", ")
    );
}

fn write_jail(output: &mut String, status: &JailStatus, flavor: StatusFlavor, indent: &str) {
    let _ = writeln!(output, "{indent}|- Filter");
    let _ = writeln!(
        output,
        "{indent}|  |- Currently failed:\t{}",
        status.currently_failed
    );
    let filter_last = branch(status.source == StatusSource::None);
    let _ = writeln!(
        output,
        "{indent}|  {filter_last} Total failed:\t{}",
        status.total_failed
    );
    match &status.source {
        StatusSource::None => {}
        StatusSource::Files(files) => {
            let _ = writeln!(output, "{indent}|  `- File list:\t{}", files.join(" "));
        }
        StatusSource::JournalMatches(groups) => {
            let groups = groups
                .iter()
                .map(|group| group.join(" "))
                .collect::<Vec<_>>();
            let _ = writeln!(
                output,
                "{indent}|  `- Journal matches:\t{}",
                groups.join(" + ")
            );
        }
    }

    let _ = writeln!(output, "{indent}`- Actions");
    let _ = writeln!(
        output,
        "{indent}   |- Currently banned:\t{}",
        status.currently_banned
    );
    let action_last = branch(flavor == StatusFlavor::Short);
    let _ = writeln!(
        output,
        "{indent}   {action_last} Total banned:\t{}",
        status.total_banned
    );
    if flavor == StatusFlavor::Basic {
        let _ = writeln!(
            output,
            "{indent}   `- Banned IP list:\t{}",
            status.banned_ips.join(" ")
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(name: &str, source: StatusSource) -> JailStatus {
        JailStatus {
            name: name.to_owned(),
            currently_failed: 2,
            total_failed: 8,
            source,
            currently_banned: 2,
            total_banned: 4,
            banned_ips: vec!["2001:db8::14".to_owned(), "192.0.2.11".to_owned()],
        }
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn banip_keeps_input_order_separator_and_original_address_spelling() {
        let addresses = [
            "2001:db8::14",
            "192.0.2.11",
            "::c000:20b",
            "::ffff:192.0.2.12",
            "::1",
        ]
        .map(|ip| ip.parse::<IpAddr>().unwrap());
        assert_eq!(
            banip(&addresses, None),
            "2001:db8::14 192.0.2.11 ::192.0.2.11 192.0.2.12 ::1\n"
        );
        let [first, second, ..] = addresses;
        assert_eq!(
            banip(&[first, second], Some(", ")),
            "2001:db8::14, 192.0.2.11\n"
        );
        assert_eq!(
            banip(&[first, second], Some("")),
            "2001:db8::14192.0.2.11\n"
        );
        assert_eq!(banip(&[], None), "\n");
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn banned_prints_original_nested_repr_and_membership_shapes() {
        let a: IpAddr = "192.0.2.11".parse().unwrap();
        let b: IpAddr = "2001:db8::14".parse().unwrap();
        assert_eq!(
            banned(&BannedReply::Jails(vec![
                ("zeta".to_owned(), vec![b, a]),
                ("alpha".to_owned(), vec![])
            ])),
            "[{'zeta': ['2001:db8::14', '192.0.2.11']}, {'alpha': []}]\n",
        );
        assert_eq!(
            banned(&BannedReply::ByAddress(vec![
                vec!["zeta".to_owned(), "bob's-test".to_owned()],
                vec![]
            ])),
            "[['zeta', \"bob's-test\"], []]\n",
        );
        assert_eq!(
            banned(&BannedReply::Addresses(vec![b, a])),
            "['2001:db8::14', '192.0.2.11']\n"
        );
        assert_eq!(banned(&BannedReply::Addresses(vec![])), "[]\n");
        assert_eq!(banned(&BannedReply::Membership(0)), "0\n");
        assert_eq!(banned(&BannedReply::Membership(1)), "1\n");
        assert_eq!(
            banned(&BannedReply::Memberships(vec![1, 0, 1])),
            "[1, 0, 1]\n"
        );
    }

    #[test]
    fn ping_global_and_missing_have_original_spelling_and_final_lf() {
        assert_eq!(ping("pong"), "Server replied: pong\n");
        assert_eq!(
            status(&[]),
            "Status\n|- Number of jail:\t0\n`- Jail list:\t\n"
        );
        assert_eq!(
            status(&["zeta".to_owned(), "alpha".to_owned()]),
            "Status\n|- Number of jail:\t2\n`- Jail list:\talpha, zeta\n"
        );
        assert_eq!(
            unknown_jail("missing"),
            "Sorry but the jail 'missing' does not exist\n"
        );
    }

    #[test]
    fn basic_file_status_preserves_indentation_tabs_and_backend_lists() {
        let status = sample(
            "offline-jail",
            StatusSource::Files(vec![
                "/var/log/z.log".to_owned(),
                "/var/log/a.log".to_owned(),
            ]),
        );
        assert_eq!(
            status_jail(&status, StatusFlavor::Basic),
            concat!(
                "Status for the jail: offline-jail\n",
                "|- Filter\n",
                "|  |- Currently failed:\t2\n",
                "|  |- Total failed:\t8\n",
                "|  `- File list:\t/var/log/z.log /var/log/a.log\n",
                "`- Actions\n",
                "   |- Currently banned:\t2\n",
                "   |- Total banned:\t4\n",
                "   `- Banned IP list:\t2001:db8::14 192.0.2.11\n",
            )
        );
    }

    #[test]
    fn journal_short_status_joins_groups_without_rendering_banned_list() {
        let status = sample(
            "offline-jail",
            StatusSource::JournalMatches(vec![
                vec![
                    "_SYSTEMD_UNIT=example.service".to_owned(),
                    "_UID=0".to_owned(),
                ],
                vec!["_COMM=example".to_owned()],
            ]),
        );
        assert_eq!(
            status_jail(&status, StatusFlavor::Short),
            concat!(
                "Status for the jail: offline-jail\n",
                "|- Filter\n",
                "|  |- Currently failed:\t2\n",
                "|  |- Total failed:\t8\n",
                "|  `- Journal matches:\t_SYSTEMD_UNIT=example.service _UID=0 + _COMM=example\n",
                "`- Actions\n",
                "   |- Currently banned:\t2\n",
                "   `- Total banned:\t4\n",
            )
        );
    }

    #[test]
    fn all_status_sorts_and_preserves_empty_lists_with_trailing_tab() {
        let mut last = sample("zeta", StatusSource::None);
        last.banned_ips.clear();
        let all = status_all(
            &[last, sample("alpha", StatusSource::Files(Vec::new()))],
            StatusFlavor::Basic,
        );
        assert_eq!(
            all,
            concat!(
                "Status\n",
                "|- Number of jail:\t2\n",
                "|- Jail list:\talpha, zeta\n",
                "`- Status for the jails:\n",
                "   |- Jail: alpha\n",
                "   |  |- Filter\n",
                "   |  |  |- Currently failed:\t2\n",
                "   |  |  |- Total failed:\t8\n",
                "   |  |  `- File list:\t\n",
                "   |  `- Actions\n",
                "   |     |- Currently banned:\t2\n",
                "   |     |- Total banned:\t4\n",
                "   |     `- Banned IP list:\t2001:db8::14 192.0.2.11\n",
                "   `- Jail: zeta\n",
                "      |- Filter\n",
                "      |  |- Currently failed:\t2\n",
                "      |  `- Total failed:\t8\n",
                "      `- Actions\n",
                "         |- Currently banned:\t2\n",
                "         |- Total banned:\t4\n",
                "         `- Banned IP list:\t\n",
            )
        );
        assert_eq!(status_all(&[], StatusFlavor::Basic), status(&[]));
    }
}
