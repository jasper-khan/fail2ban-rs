use super::*;

fn write(base: &Path, path: &str, text: impl AsRef<[u8]>) {
    let file = base.join(path);
    fs::create_dir_all(file.parent().unwrap()).unwrap();
    fs::write(&file, text).unwrap();
}

fn paths<'a>(base: &Path, config: &'a LayeredConfig) -> Vec<&'a Path> {
    config
        .files
        .iter()
        .map(|path| path.strip_prefix(base).unwrap())
        .collect()
}

#[test]
fn root_layers_apply_conf_before_local_with_sorted_dropins() {
    let temp = tempfile::tempdir().unwrap();
    let base = temp.path();
    for (name, value) in [
        ("jail.d/99.conf", "last-conf"),
        ("jail.d/01.conf", "first-conf"),
        ("jail.d/12.local", "last-local"),
        ("jail.d/11.local", "first-local"),
        ("jail.conf", "main"),
        ("jail.local", "root-local"),
        ("jail.d/.hidden.local", "ignored-hidden"),
        ("jail.d/20.conf.bak", "ignored-extension"),
    ] {
        write(
            base,
            name,
            format!("[DEFAULT]\norigin={value}\n[sshd]\nsource={value}\n"),
        );
    }
    let config = read(base, "jail").unwrap().unwrap();
    let order = [
        "jail.conf",
        "jail.d/01.conf",
        "jail.d/99.conf",
        "jail.local",
        "jail.d/11.local",
        "jail.d/12.local",
    ];
    assert_eq!(paths(base, &config), order.map(Path::new));
    assert_eq!(config.defaults["origin"], "last-local");
    assert_eq!(config.sections["sshd"]["source"], "last-local");
    assert_eq!(config.sections["KNOWN/sshd"]["source"], "first-local");
    assert_eq!(config.section_order, ["sshd", "KNOWN/sshd"]);
}

#[test]
fn nesting_expands_local_companions_and_preserves_repeated_sibling_includes() {
    let temp = tempfile::tempdir().unwrap();
    let base = temp.path();
    write(
        base,
        "jail.conf",
        "[DEFAULT]\nchild=shared/a.conf\n[INCLUDES]\nbefore=%(child)s\nafter=%(child)s\n[demo]\nv=root\n",
    );
    write(
        base,
        "shared/a.conf",
        "[INCLUDES]\nbefore=sub/b.conf\nafter=../absent.conf\n[demo]\nv=a\n",
    );
    write(base, "shared/a.local", "[demo]\nv=a-local\n");
    write(base, "shared/sub/b.conf", "[demo]\nbase=true\n");
    write(base, "shared/sub/b.local", "[demo]\nlocal=true\n");
    let config = read(base, "jail").unwrap().unwrap();
    let order = [
        "shared/sub/b.conf",
        "shared/sub/b.local",
        "shared/a.conf",
        "shared/a.local",
        "jail.conf",
        "shared/sub/b.conf",
        "shared/sub/b.local",
        "shared/a.conf",
        "shared/a.local",
    ];
    assert_eq!(paths(base, &config), order.map(Path::new));
    assert_eq!(config.sections["demo"]["v"], "a-local");
    assert_eq!(config.sections["KNOWN/demo"]["v"], "a");
}

#[test]
fn direct_cycles_check_ancestors_not_global_seen_and_aliases_are_bounded() {
    let temp = tempfile::tempdir().unwrap();
    let base = temp.path();
    write(base, "jail.conf", "[INCLUDES]\nbefore=jail.conf\n");
    let config = read(base, "jail").unwrap().unwrap();
    assert_eq!(
        paths(base, &config),
        ["jail.conf", "jail.conf"].map(Path::new)
    );

    #[cfg(unix)]
    {
        write(base, "jail.conf", "[INCLUDES]\nbefore=./jail.conf\n");
        assert!(
            read(base, "jail")
                .unwrap_err()
                .to_string()
                .contains("recursion limit")
        );
    }
}

#[test]
fn root_absence_and_invalid_utf8_are_false_but_malformed_includes_are_errors() {
    let temp = tempfile::tempdir().unwrap();
    let base = temp.path();
    assert!(read(&base.join("missing-base"), "jail").is_err());
    assert!(read(base, "jail").unwrap().is_none());
    write(base, "jail.local", "[demo]\nv=local-only\n");
    assert!(read(base, "jail").unwrap().is_some());
    write(base, "jail.conf", [0xff, 0x0a]);
    assert!(read(base, "jail").unwrap().is_none());

    write(
        base,
        "jail.conf",
        "[INCLUDES]\nbefore=invalid-utf8.conf\n       absent.conf\n       malformed.conf\n",
    );
    write(base, "invalid-utf8.conf", [0xff, 0x0a]);
    assert!(read(base, "jail").unwrap().is_some());
    write(base, "malformed.conf", "outside=section\n");
    let error = read(base, "jail").unwrap_err().to_string();
    assert!(error.contains("malformed.conf") && error.contains("missing section header"));
}

#[test]
fn section_conditionals_merge_raw_and_defaults_are_not_copied_into_sections() {
    let temp = tempfile::tempdir().unwrap();
    let base = temp.path();
    write(
        base,
        "jail.conf",
        "[DEFAULT]\norigin=default\n[demo]\nchoice=original\n[demo?backend=systemd]\nchoice=branch\n__name__=drop\n[empty]\n",
    );
    write(base, "jail.local", "[demo]\nchoice=%(known/choice)s\n");
    let config = read(base, "jail").unwrap().unwrap();
    let demo = &config.sections["demo"];
    assert_eq!(demo["choice"], "%(known/choice)s");
    assert_eq!(demo["choice?backend=systemd"], "branch");
    assert_eq!(config.sections["KNOWN/demo"]["choice"], "original");
    assert!(!demo.contains_key("origin") && !demo.contains_key("__name__?backend=systemd"));
    assert!(config.sections["empty"].is_empty());
}

#[test]
fn include_interpolation_uses_local_values_and_errors_on_missing_refs() {
    let temp = tempfile::tempdir().unwrap();
    let base = temp.path();
    write(
        base,
        "jail.conf",
        "[DEFAULT]\nbefore=%(child)s\nchild=ignored.conf\n[INCLUDES]\nchild=inherited.conf\n",
    );
    write(base, "inherited.conf", "[demo]\nv=included\n");
    write(base, "jail.local", "[DEFAULT]\nchild=other.conf\n");
    let config = read(base, "jail").unwrap().unwrap();
    assert_eq!(
        paths(base, &config),
        ["inherited.conf", "jail.conf", "jail.local"].map(Path::new)
    );
    write(base, "jail.conf", "[INCLUDES]\nbefore=%(undefined)s\n");
    let error = read(base, "jail").unwrap_err().to_string();
    assert!(error.contains("jail.conf") && error.contains("undefined"));
}

#[test]
fn include_slash_aliases_require_original_spelling() {
    let temp = tempfile::tempdir().unwrap();
    let base = temp.path();
    write(base, "included.conf", "[demo]\nvalue=linked\n");
    for reference in [
        "default/file",
        "fixture/file",
        "DEFAULT/file",
        "Fixture/file",
    ] {
        write(
            base,
            "jail.conf",
            format!(
                "[DEFAULT]\nfile=included.conf\n[fixture]\nfile=included.conf\n[INCLUDES]\nbefore=%({reference})s\n"
            ),
        );
        let result = read(base, "jail");
        if reference.chars().all(|ch| !ch.is_uppercase()) {
            let config = result.unwrap().unwrap();
            assert_eq!(config.sections["demo"]["value"], "linked");
        } else {
            assert!(
                result
                    .unwrap_err()
                    .to_string()
                    .contains("not a valid option name")
            );
        }
    }
}
