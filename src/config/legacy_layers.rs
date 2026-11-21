//! File discovery and raw merging for the original Fail2Ban configuration.
//!
//! Mirrors Fail2Ban 1.1.1 ConfigReaderUnshared and, with immutable sources,
//! its uncached SafeConfigParserWithIncludes traversal. Effective values stay
//! raw; interpolation here is only for a file's own include declarations.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};

use super::{legacy_ini, legacy_interp};

type Options = BTreeMap<String, String>;

// Lexical aliases can defeat the upstream exact-path ancestor checks. Bound
// stack use in that case rather than overflowing it during configuration load.
const INCLUDE_DEPTH_LIMIT: usize = 128;

#[derive(Debug, Default)]
pub(super) struct LayeredConfig {
    /// Effective merge order. Repeated includes remain repeated.
    pub(super) files: Vec<PathBuf>,
    pub(super) defaults: Options,
    /// Raw sections, including Fail2Ban's internal KNOWN/ snapshots.
    pub(super) sections: BTreeMap<String, Options>,
    /// First insertion order for explicit and synthetic raw sections.
    pub(super) section_order: Vec<String>,
}

/// Read a config name without its extension, e.g. `jail` or `filter.d/sshd`.
///
/// `None` is the upstream false result: no selected root config, or an
/// existing root config which was not readable. Unreadable include-only
/// resources are optional; malformed INI or include interpolation is an error.
pub(super) fn read(base: &Path, name: &str) -> Result<Option<LayeredConfig>> {
    // Upstream strips trailing slashes before checking whether the base exists.
    if base
        .as_os_str()
        .as_encoded_bytes()
        .iter()
        .all(|&ch| ch == b'/')
        || !base.exists()
    {
        return Err(Error::config(format!(
            "base configuration directory {} does not exist",
            base.display()
        )));
    }
    let basename = if name.starts_with("./") {
        absolute_normalized(Path::new(name))?
    } else {
        base.join(name)
    };
    let dropin = append_suffix(&basename, ".d");
    let mut roots = vec![append_suffix(&basename, ".conf")];
    roots.extend(dropins(&dropin, "conf"));
    roots.push(append_suffix(&basename, ".local"));
    roots.extend(dropins(&dropin, "local"));
    roots.retain(|path| path.exists());
    if roots.is_empty() {
        return Ok(None);
    }

    let mut config = LayeredConfig::default();
    let mut ancestors = Vec::new();
    for resource in with_local_companions(&roots) {
        visit(&resource, &mut ancestors, &mut config)?;
    }
    if roots
        .iter()
        .any(|root| !config.files.iter().any(|file| same_path(file, root)))
    {
        return Ok(None);
    }
    Ok(Some(config))
}

/// Upstream explicitly makes a name beginning with "./" relative to the
/// working directory (not to the base), using lexical normalization.
fn absolute_normalized(path: &Path) -> Result<PathBuf> {
    use std::path::Component;
    let absolute = std::env::current_dir()
        .map_err(|err| Error::io("locating original Fail2Ban configuration", err))?
        .join(path);
    let mut result = PathBuf::new();
    for part in absolute.components() {
        match part {
            Component::CurDir => {}
            Component::ParentDir => {
                if result.parent().is_some() {
                    result.pop();
                }
            }
            _ => result.push(part),
        }
    }
    Ok(result)
}

fn append_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut path = path.as_os_str().to_os_string();
    path.push(suffix);
    path.into()
}

fn dropins(dir: &Path, extension: &str) -> Vec<PathBuf> {
    let mut paths = fs::read_dir(dir)
        .into_iter()
        .flatten()
        .filter_map(std::result::Result::ok)
        .filter(|entry| !entry.file_name().as_encoded_bytes().starts_with(b"."))
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == extension))
        .collect::<Vec<_>>();
    paths.sort_unstable();
    paths
}

fn same_path(a: &Path, b: &Path) -> bool {
    // Path equality normalizes repeated separators and most "." segments;
    // upstream compares the source path spelling, not filesystem identity.
    a.as_os_str() == b.as_os_str()
}

#[cfg(unix)]
fn source_dir(path: &Path) -> &Path {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    // Path::parent normalizes away a final "." in the parent. The original
    // posixpath.dirname preserves it, which matters to exact-path recursion.
    let bytes = path.as_os_str().as_bytes();
    let split = bytes
        .iter()
        .rposition(|&ch| ch == b'/')
        .map_or(0, |i| i + 1);
    let head = bytes.get(..split).unwrap_or_default();
    let end = head
        .iter()
        .rposition(|&ch| ch != b'/')
        .map_or(head.len(), |i| i + 1);
    Path::new(OsStr::from_bytes(head.get(..end).unwrap_or_default()))
}

#[cfg(not(unix))]
fn source_dir(path: &Path) -> &Path {
    path.parent().unwrap_or_else(|| Path::new(""))
}

fn with_local_companions(paths: &[PathBuf]) -> Vec<PathBuf> {
    let mut result = Vec::new();
    for path in paths {
        result.push(path.clone());
        let local = path.with_extension("local");
        if !paths.iter().any(|p| same_path(p, &local)) && local.is_file() {
            result.push(local);
        }
    }
    result
}

fn visit(resource: &Path, ancestors: &mut Vec<PathBuf>, config: &mut LayeredConfig) -> Result<()> {
    if ancestors.len() == INCLUDE_DEPTH_LIMIT {
        return Err(Error::config(format!(
            "Fail2Ban include recursion limit at {}",
            resource.display()
        )));
    }
    // In Python, opening/reading OSErrors and invalid UTF-8 are skipped during
    // include discovery. Root entries are checked for participation afterward.
    let Ok(bytes) = fs::read(resource) else {
        return Ok(());
    };
    let Ok(text) = std::str::from_utf8(&bytes) else {
        return Ok(());
    };
    let layer = RawLayer::from(legacy_ini::parse(text, resource)?);
    let before = layer.includes(resource, "before")?;
    for path in before {
        visit_include(resource, &path, ancestors, config)?;
    }
    let after = layer.includes(resource, "after")?;
    config.merge(resource, layer);
    for path in after {
        visit_include(resource, &path, ancestors, config)?;
    }
    Ok(())
}

fn visit_include(
    resource: &Path,
    child: &Path,
    ancestors: &mut Vec<PathBuf>,
    config: &mut LayeredConfig,
) -> Result<()> {
    if ancestors.iter().any(|path| same_path(path, child)) {
        return Ok(());
    }
    ancestors.push(resource.to_path_buf());
    let result = with_local_companions(&[child.to_path_buf()])
        .iter()
        .try_for_each(|path| visit(path, ancestors, config));
    ancestors.pop();
    result
}

#[derive(Default)]
struct RawLayer {
    defaults: Options,
    sections: Vec<(String, Options)>,
}

impl From<legacy_ini::Document> for RawLayer {
    fn from(doc: legacy_ini::Document) -> Self {
        let mut grouped = BTreeMap::<String, Options>::new();
        for entry in doc.entries {
            grouped
                .entry(entry.section)
                .or_default()
                .insert(entry.option, entry.value);
        }
        let defaults = grouped.remove("DEFAULT").unwrap_or_default();
        let sections = doc
            .sections
            .into_iter()
            .filter(|name| name != "DEFAULT")
            .map(|name| {
                let options = grouped.remove(&name).unwrap_or_default();
                (name, options)
            })
            .collect();
        Self { defaults, sections }
    }
}

impl RawLayer {
    fn includes(&self, resource: &Path, option: &str) -> Result<Vec<PathBuf>> {
        let expanded = legacy_interp::get_effective(
            "INCLUDES",
            option,
            &self.defaults,
            |name| self.section(name),
            None,
        )
        .map_err(|err| {
            Error::config(format!(
                "{}: [INCLUDES] {option}: {err}",
                resource.display()
            ))
        })?;
        let Some(expanded) = expanded else {
            return Ok(Vec::new());
        };
        let dir = source_dir(resource);
        Ok(expanded.split('\n').map(|child| dir.join(child)).collect())
    }

    fn section(&self, name: &str) -> Option<&Options> {
        self.sections
            .iter()
            .find_map(|(key, options)| (key == name).then_some(options))
    }
}

impl LayeredConfig {
    fn merge(&mut self, path: &Path, layer: RawLayer) {
        self.files.push(path.to_path_buf());
        self.defaults.extend(layer.defaults);
        for (name, options) in layer.sections {
            let (name, options) = conditional_section(name, options);
            if let Some(current) = self.sections.get(&name) {
                // KNOWN holds only values overwritten by this or earlier
                // merges, not those which never changed.
                let known = current
                    .iter()
                    .filter(|(key, _)| options.contains_key(*key))
                    .map(|(key, value)| (key.clone(), value.clone()))
                    .collect::<Options>();
                self.section_mut(&format!("KNOWN/{name}")).extend(known);
            }
            self.section_mut(&name).extend(options);
        }
    }

    fn section_mut(&mut self, name: &str) -> &mut Options {
        self.sections.entry(name.to_owned()).or_insert_with(|| {
            self.section_order.push(name.to_owned());
            Options::new()
        })
    }
}

fn conditional_section(name: String, mut options: Options) -> (String, Options) {
    if let Some((prefix, condition)) = name.split_once('?')
        && !prefix.is_empty()
        && !condition.is_empty()
        && prefix.chars().all(|ch| ch.is_alphanumeric() || ch == '_')
    {
        options.remove("__name__");
        return (
            prefix.to_owned(),
            options
                .into_iter()
                .map(|(key, value)| (format!("{key}?{condition}"), value))
                .collect(),
        );
    }
    (name, options)
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::unwrap_used)]
#[path = "legacy_layers_test.rs"]
mod tests;
