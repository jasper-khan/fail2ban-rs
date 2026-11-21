use super::*;

fn config(source: &str) -> LayeredConfig {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("filter.d");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("demo.conf"), source).unwrap();
    read(tmp.path(), "demo").unwrap().unwrap()
}

#[test]
fn percent_preselection_and_angle_precedence_are_separate_stages() {
    let config = config(
        "[Definition]\ntoken=definition\nfailregex=^%(token)s <token> <HOST>$\nmaxlines=2\n\
         [Init]\ntoken=init\nmaxlines=3\n",
    );
    let jail = Options::from([("token".to_owned(), "jail".to_owned())]);
    let explicit = Options::from([
        ("token".to_owned(), "call".to_owned()),
        ("maxlines".to_owned(), "8".to_owned()),
    ]);
    let empty = Options::new();
    for (call, regex, lines) in [
        (&empty, "^jail init <HOST>$", 3),
        (&explicit, "^call call <HOST>$", 8),
    ] {
        let out = resolve(
            &config,
            &Parameters {
                backend: "auto",
                jail: &jail,
                call,
                all: false,
            },
        )
        .unwrap();
        assert_eq!(out.options["failregex"], regex);
        assert_eq!(out.options["known/token"], "init");
        assert_eq!(out.maxlines, Some(lines));
    }
}

#[test]
fn backend_auto_logtype_and_explicit_logtype_select_original_sections() {
    let config = config(
        "[DEFAULT]\nlogtype=file\n[Definition]\nprefregex=<lt_<logtype>/prefix><F-CONTENT>.*</F-CONTENT>\n\
         [Init]\nlogtype=ignored\n[lt_file]\nprefix=FILE:\n[lt_journal]\nprefix=JOURNAL:\n[lt_short]\nprefix=SHORT:\n",
    );
    let empty = Options::new();
    let short = Options::from([("logtype".to_owned(), "short".to_owned())]);
    for (backend, call, prefix) in [
        ("polling", &empty, "FILE:"),
        ("systemd[journalflags=1]", &empty, "JOURNAL:"),
        ("systemd", &short, "SHORT:"),
    ] {
        let out = resolve(
            &config,
            &Parameters {
                backend,
                jail: &empty,
                call,
                all: false,
            },
        )
        .unwrap();
        assert_eq!(
            out.options["prefregex"],
            format!("{prefix}<F-CONTENT>.*</F-CONTENT>")
        );
    }
}

#[test]
fn definition_own_logtype_prevents_automatic_injection() {
    let config = config(
        "[Definition]\nlogtype=short\nprefregex=<lt_<logtype>/prefix>\n[lt_short]\nprefix=SHORT:\n",
    );
    let empty = Options::new();
    let out = resolve(
        &config,
        &Parameters {
            backend: "polling",
            jail: &empty,
            call: &empty,
            all: false,
        },
    )
    .unwrap();
    assert_eq!(out.options["prefregex"], "SHORT:");
    assert!(!out.options.contains_key("logtype"));
}

#[test]
fn all_mode_adds_extra_definition_values_without_passed_vars() {
    let config = config(
        "[DEFAULT]\nextra=default\ninherited=ignored\n[Definition]\nextra=defined\nusedns=no\nfailregex=^%(extra)s <HOST>$\n",
    );
    let jail = Options::from([
        ("extra".to_owned(), "jail".to_owned()),
        ("usedns".to_owned(), "yes".to_owned()),
    ]);
    let empty = Options::new();
    for all in [false, true] {
        let out = resolve(
            &config,
            &Parameters {
                backend: "auto",
                jail: &jail,
                call: &empty,
                all,
            },
        )
        .unwrap();
        assert_eq!(out.options["failregex"], "^jail <HOST>$");
        assert!(!out.options.contains_key("inherited"));
        assert_eq!(
            out.options.get("extra").map(String::as_str),
            all.then_some("defined")
        );
        assert_eq!(
            out.options.get("usedns").map(String::as_str),
            all.then_some("no")
        );
    }
}

#[test]
fn conditional_base_tags_remain_literal_and_skip_expansion() {
    let config = config(
        "[Definition]\nfailregex=<token>:<token?context> <ADDR>\n\
         [Init]\ntoken=<bad-tag>\n[Init?context]\ntoken=conditional\n",
    );
    let empty = Options::new();
    let jail = Options::from([("token".to_owned(), "external".to_owned())]);
    let out = resolve(
        &config,
        &Parameters {
            backend: "auto",
            jail: &jail,
            call: &empty,
            all: false,
        },
    )
    .unwrap();
    assert_eq!(out.options["token"], "<bad-tag>");
    assert_eq!(out.options["token?context"], "external");
    assert_eq!(out.options["failregex"], "<token>:external <ADDR>");
}

#[test]
fn integer_conversion_is_after_angle_substitution() {
    let config = config("[Definition]\nmaxlines=<count>\ncount=1_024\n");
    let empty = Options::new();
    for (call, expected) in [
        (Options::new(), Some(1024)),
        (
            Options::from([("count".to_owned(), "bad".to_owned())]),
            None,
        ),
    ] {
        let out = resolve(
            &config,
            &Parameters {
                backend: "auto",
                jail: &empty,
                call: &call,
                all: false,
            },
        )
        .unwrap();
        assert_eq!(out.maxlines, expected);
        assert!(!out.options.contains_key("maxlines"));
    }
}
