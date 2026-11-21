//! Raw parsing of original Fail2Ban configuration files.
//!
//! Fail2Ban 1.1.1 uses Python's strict ConfigParser with inline semicolon
//! comments. This layer reads one file: it does not load includes, inherit
//! defaults, interpolate values, or merge settings from different files.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use crate::error::{Error, Result};

#[derive(Debug, Default)]
pub(super) struct Document {
    /// Explicit section names in first-seen order, including `DEFAULT` if declared.
    pub(super) sections: Vec<String>,
    /// Options in their original order.
    pub(super) entries: Vec<Entry>,
}

#[derive(Debug)]
pub(super) struct Entry {
    pub(super) section: String,
    pub(super) option: String,
    pub(super) value: String,
    /// One-based line on which the option begins.
    pub(super) line: usize,
}

/// Parse text as a single source file, retaining interpolation syntax literally.
pub(super) fn parse(input: &str, path: &Path) -> Result<Document> {
    let mut document = Document::default();
    let mut sections = HashMap::new();
    let mut options = HashSet::new();
    let mut section: Option<(&str, usize)> = None;
    let mut pending: Option<usize> = None;
    let mut indent_level = 0;
    let mut malformed = Vec::new();

    // Python opens config files with universal newlines (LF, CRLF or CR).
    let lines = input
        .split_terminator('\n')
        .flat_map(|line| line.strip_suffix('\r').unwrap_or(line).split('\r'));
    for (index, line) in lines.enumerate() {
        let line_number = index + 1;
        let comment = comment_start(line);
        let value = comment
            .and_then(|start| line.get(..start))
            .unwrap_or(line)
            .trim_matches(is_space);
        if value.is_empty() {
            if comment.is_none()
                && let Some(entry) = pending.and_then(|index| document.entries.get_mut(index))
            {
                entry.value.push('\n');
            }
            continue;
        }

        // Count whitespace characters, not bytes or visual columns. An
        // indented token is part of the preceding value before interpreting it
        // as either a section or an option, even if it contains '=' or ':'.
        let indentation = line.chars().take_while(|&ch| is_space(ch)).count();
        if indentation > indent_level
            && let Some(entry) = pending.and_then(|index| document.entries.get_mut(index))
        {
            entry.value.push('\n');
            entry.value.push_str(value);
            continue;
        }
        indent_level = indentation;

        if let Some(name) = section_name(value) {
            let id = if let Some(&id) = sections.get(name) {
                if name != "DEFAULT" {
                    return Err(at(
                        path,
                        line_number,
                        &format!("duplicate section [{name}]"),
                    ));
                }
                id
            } else {
                let id = document.sections.len();
                sections.insert(name, id);
                document.sections.push(name.to_owned());
                id
            };
            section = Some((name, id));
            pending = None;
            continue;
        }

        let Some((name, section_id)) = section else {
            return Err(at(path, line_number, "missing section header"));
        };
        let Some((key, value)) = value.split_once(['=', ':']) else {
            malformed.push(line_number);
            continue;
        };
        let option = key.trim_end_matches(is_space).to_lowercase();
        if option.is_empty() {
            malformed.push(line_number);
            pending = None;
            continue;
        }
        if !options.insert((section_id, option.clone())) {
            return Err(at(
                path,
                line_number,
                &format!("duplicate option {option:?} in [{name}]"),
            ));
        }
        pending = Some(document.entries.len());
        document.entries.push(Entry {
            section: name.to_owned(),
            option,
            value: value.trim_matches(is_space).to_owned(),
            line: line_number,
        });
    }

    if !malformed.is_empty() {
        let details = malformed
            .iter()
            .map(|line| format!("{}:{line}: malformed option", path.display()))
            .collect::<Vec<_>>()
            .join("; ");
        return Err(Error::config(details));
    }
    for entry in &mut document.entries {
        let value_len = entry.value.trim_end_matches(is_space).len();
        entry.value.truncate(value_len);
    }
    Ok(document)
}

fn at(path: &Path, line: usize, message: &str) -> Error {
    Error::config(format!("{}:{line}: {message}", path.display()))
}

fn is_space(ch: char) -> bool {
    // Python's str.isspace also recognizes these ASCII information separators.
    ch.is_whitespace() || matches!(ch, '\u{001c}'..='\u{001f}')
}

fn comment_start(line: &str) -> Option<usize> {
    if line.trim_start_matches(is_space).starts_with(['#', ';']) {
        return Some(0);
    }
    let mut previous_space = false;
    for (index, ch) in line.char_indices() {
        if ch == ';' && previous_space {
            return Some(index);
        }
        previous_space = is_space(ch);
    }
    None
}

fn section_name(line: &str) -> Option<&str> {
    // ConfigParser greedily matches a nonempty name through the final ']',
    // preserves whitespace inside the brackets and ignores the remaining text.
    let rest = line.strip_prefix('[')?;
    let (name, _) = rest.rsplit_once(']')?;
    (!name.is_empty()).then_some(name)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn path() -> &'static Path {
        Path::new("filter.d/example.conf")
    }

    fn entries(doc: &Document) -> Vec<(&str, &str, &str, usize)> {
        doc.entries
            .iter()
            .map(|entry| {
                (
                    entry.section.as_str(),
                    entry.option.as_str(),
                    entry.value.as_str(),
                    entry.line,
                )
            })
            .collect()
    }

    #[test]
    fn raw_values_keep_section_case_and_literals() {
        let doc = parse(
            concat!(
                "# Comment\n",
                "[DEFAULT]\n",
                "B = abc\n",
                "C = d ; inline comment\n",
                "[Definition] trailing text\n",
                "Value : 4%(b)s and ${b} # literal hash\n",
                "S With Spaces = literal;semicolon\n",
                "datepattern = %%Y %%m %%d\n",
                "[definition]\n",
                "VALUE=other\n",
                "[ default ]\n",
                "[DEFAULT]\n",
                "More = yes\n",
            ),
            path(),
        )
        .unwrap();
        assert_eq!(
            doc.sections,
            ["DEFAULT", "Definition", "definition", " default "]
        );
        assert_eq!(
            entries(&doc),
            [
                ("DEFAULT", "b", "abc", 3),
                ("DEFAULT", "c", "d", 4),
                ("Definition", "value", "4%(b)s and ${b} # literal hash", 6),
                ("Definition", "s with spaces", "literal;semicolon", 7),
                ("Definition", "datepattern", "%%Y %%m %%d", 8),
                ("definition", "value", "other", 10),
                ("DEFAULT", "more", "yes", 13),
            ],
        );
    }

    #[test]
    fn indentation_continuations_and_blank_lines_match_upstream() {
        let doc = parse(
            concat!(
                "[Definition]\r\n",
                "  failregex = first\r",
                "    second:contains=delimiters ; stripped\r\n",
                "    # comment is not a blank line\r\n",
                "\n",
                "    [third] still a continuation\r\n",
                "  ignoreregex =\r\n",
                "    value;kept\r\n",
                "\r\n",
                "[Init]\r\n",
                "mode=normal\r\n",
            ),
            path(),
        )
        .unwrap();
        assert_eq!(doc.sections, ["Definition", "Init"]);
        assert_eq!(
            entries(&doc),
            [
                (
                    "Definition",
                    "failregex",
                    "first\nsecond:contains=delimiters\n\n[third] still a continuation",
                    2
                ),
                ("Definition", "ignoreregex", "\nvalue;kept", 7),
                ("Init", "mode", "normal", 11),
            ],
        );
    }

    #[test]
    fn rejects_duplicate_sections_and_case_folded_options_in_one_file() {
        for (source, line, detail) in [
            ("[Test]\n[Test]\n", 2, "duplicate section"),
            ("[Test]\nKey=x\nkEY:y\n", 3, "duplicate option"),
            (
                "[DEFAULT]\nKey=x\n[DEFAULT]\nKEY=y\n",
                4,
                "duplicate option",
            ),
        ] {
            let message = parse(source, path()).unwrap_err().to_string();
            assert!(message.contains(&format!("filter.d/example.conf:{line}: {detail}")));
        }
    }

    #[test]
    fn errors_identify_source_and_invalid_lines() {
        let error = parse("# heading\nkey=value\n", path())
            .unwrap_err()
            .to_string();
        assert!(error.contains("filter.d/example.conf:2: missing section header"));

        let error = parse("[Test]\nno separator\nvalid=x\n= no key\n", path())
            .unwrap_err()
            .to_string();
        assert!(error.contains("filter.d/example.conf:2: malformed option"));
        assert!(error.contains("filter.d/example.conf:4: malformed option"));
    }

    #[test]
    fn empty_and_permissive_section_headers() {
        let empty = parse("# only a comment\n; another\n", path()).unwrap();
        assert!(empty.sections.is_empty() && empty.entries.is_empty());

        let doc = parse("[ spaces ] followed by [text]\n[Empty]\n", path()).unwrap();
        assert_eq!(doc.sections, [" spaces ] followed by [text", "Empty"]);
        assert!(doc.entries.is_empty());

        let message = parse("[]\n", path()).unwrap_err().to_string();
        assert!(message.contains("missing section header"));
    }
}
