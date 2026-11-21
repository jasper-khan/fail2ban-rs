use super::*;

const WHEN: &str = "2024/01/02 03:04:05";
const UNIX_SECONDS: i64 = 1_704_164_645;
const PREFIX: &str = r"^\s*\[error\] <F-CONTENT>.*</F-CONTENT>, client: <ADDR>$";
const FAIL: &str = r#"^user "<F-USER>[^"]+</F-USER>": password mismatch$"#;

fn filter(prefix: Option<&str>, failures: &str, ignores: &str) -> ResolvedFilter {
    let mut options = [
        ("logtype", "file"),
        ("datepattern", "{^LN-BEG}"),
        ("failregex", failures),
        ("ignoreregex", ignores),
    ]
    .into_iter()
    .map(|(a, b)| (a.to_owned(), b.to_owned()))
    .collect::<std::collections::BTreeMap<_, _>>();
    if let Some(prefix) = prefix {
        options.insert("prefregex".to_owned(), prefix.to_owned());
    }
    ResolvedFilter {
        options,
        maxlines: Some(1),
    }
}

#[test]
fn prefix_narrows_record_and_carries_its_address() {
    let matcher = LegacyMatcher::compile(&filter(Some(PREFIX), FAIL, "")).unwrap();
    for address in ["192.0.2.25", "[2001:db8::25]", "::ffff:192.0.2.25"] {
        let line = format!(r#"{WHEN} [error] user "demo": password mismatch, client: {address}"#);
        let ip = if address.starts_with('[') {
            "2001:db8::25"
        } else {
            "192.0.2.25"
        };
        assert_eq!(
            matcher.evaluate(&line),
            LineResult::Matched(Failure {
                ip: ip.parse().unwrap(),
                timestamp: UNIX_SECONDS,
                pattern_idx: 0,
                user: Some("demo".to_owned()),
            })
        );
    }
}

#[test]
fn late_ignore_uses_only_content_and_requires_a_failure() {
    let line = format!(r#"{WHEN} [error] user "demo": password mismatch, client: 192.0.2.25"#);
    let content = LegacyMatcher::compile(&filter(Some(PREFIX), FAIL, r#"^user "demo":"#)).unwrap();
    assert_eq!(
        content.evaluate(&line),
        LineResult::Ignored { pattern_idx: 0 }
    );
    let outer = LegacyMatcher::compile(&filter(Some(PREFIX), FAIL, "client:")).unwrap();
    assert!(matches!(outer.evaluate(&line), LineResult::Matched(_)));
    let event = format!("{WHEN} [error] service ready, client: 192.0.2.25");
    assert_eq!(content.evaluate(&event), LineResult::Miss);
}

#[test]
fn sparse_early_ignore_checks_entire_stripped_record() {
    let failure_rules = format!("{FAIL}\n^alpha$\n^bravo$\n^charlie$");
    let rule =
        LegacyMatcher::compile(&filter(Some(PREFIX), &failure_rules, r"^\s*\[notice\]")).unwrap();
    let line = format!("{WHEN} [notice] service ready, client: 192.0.2.25");
    assert_eq!(rule.evaluate(&line), LineResult::Ignored { pattern_idx: 0 });
}

#[test]
fn empty_content_keeps_original_record_and_failregex_order() {
    let rule = LegacyMatcher::compile(&filter(
        Some(r"^\s*<F-CONTENT></F-CONTENT> event from <ADDR>$"),
        "^impossible$\n^ +event from .+$\n^.*$",
        "",
    ))
    .unwrap();
    let line = format!("{WHEN}  event from 192.0.2.25");
    assert!(matches!(
        rule.evaluate(&line),
        LineResult::Matched(Failure { pattern_idx: 1, .. })
    ));
}

#[test]
fn match_requires_supported_date_prefix_failure_and_one_record() {
    let matcher = LegacyMatcher::compile(&filter(Some(PREFIX), FAIL, "")).unwrap();
    for line in [
        r#"[error] user "demo": password mismatch, client: 192.0.2.25"#.to_owned(),
        r#"2024/02/30 03:04:05 [error] user "demo": password mismatch, client: 192.0.2.25"#
            .to_owned(),
        format!(r#"{WHEN} [notice] user "demo": password mismatch, client: 192.0.2.25"#),
        format!(r#"{WHEN} [error] user "demo": success, client: 192.0.2.25"#),
        format!("{WHEN} [error] ordinary status\nsecond record"),
    ] {
        assert_eq!(matcher.evaluate(&line), LineResult::Miss);
    }
}

#[test]
fn rejects_unknown_date_dns_multiline_and_conflicting_address_sources() {
    let mut configured = filter(Some(PREFIX), FAIL, "");
    configured.maxlines = Some(2);
    assert!(
        LegacyMatcher::compile(&configured)
            .unwrap_err()
            .to_string()
            .contains("multiline")
    );
    configured.maxlines = Some(1);
    configured
        .options
        .insert("datepattern".into(), "none".into());
    assert!(
        LegacyMatcher::compile(&configured)
            .unwrap_err()
            .to_string()
            .contains("datepattern")
    );

    let mut host = filter(None, r"^\s*event from <HOST>$", "");
    assert!(
        LegacyMatcher::compile(&host)
            .unwrap_err()
            .to_string()
            .contains("usedns=no")
    );
    host.options.insert("usedns".to_owned(), "no".to_owned());
    assert!(LegacyMatcher::compile(&host).is_ok());
    let both = filter(Some(PREFIX), r"^event from <ADDR>$", "");
    assert!(
        LegacyMatcher::compile(&both)
            .unwrap_err()
            .to_string()
            .contains("both prefregex and failregex")
    );
}
