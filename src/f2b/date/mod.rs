//! Pure-Rust port of Fail2Ban 1.1.1 `fail2ban/server/datedetector.py`.
//!
//! Exports [`DateDetector`] along with the [`strptime`] and [`template`] modules.

pub mod strptime;
pub mod template;

use crate::error::Result;
use crate::logging::{LogLevel, log_msg};

use self::strptime::validate_timezone;
use self::template::{DateTemplate, unbound_pattern};

/// All 17 upstream Fail2Ban 1.1.1 `DateDetectorCache._DEFAULT_TEMPLATES` in exact order.
pub const DEFAULT_TEMPLATES: &[&str] = &[
    // ISO 8601 / standard YYYY-MM-DD HH:MM:SS(.frac)(+tz)
    r"%ExY(?P<_sep>[-/.])%m(?P=_sep)%d(?:T|  ?)%H:%M:%S(?:[.,]%f)?(?:\s*%z)?",
    // Standard syslog: (Sun )Dec 04 04:47:44(.frac)( 2005)
    r"(?:%a )?%b %d %k:%M:%S(?:\.%f)?(?: %ExY)?",
    // Assp / Exim / etc: (Sun )Dec 04 2005 04:47:44(.frac)
    r"(?:%a )?%b %d %ExY %k:%M:%S(?:\.%f)?",
    // DD-MM-YYYY HH:MM:SS or DD/MM/YY HH:MM:SS
    r"%d(?P<_sep>[-/])%m(?P=_sep)(?:%ExY|%Exy) %k:%M:%S",
    // Apache CLF: 10/Oct/2000:13:55:36 -0700
    r"%d(?P<_sep>[-/])%b(?P=_sep)%ExY[ :]?%H:%M:%S(?:\.%f)?(?: %z)?",
    // 10/25/2024:13:55:36
    r"%m/%d/%ExY:%H:%M:%S",
    // 10-25-2024 13:55:36(.frac)
    r"%m-%d-%ExY %k:%M:%S(?:\.%f)?",
    // Unix epoch (audit(...), [epoch], ^epoch)
    r"EPOCH",
    // Bare HH:MM:SS anchored at line begin
    r"{^LN-BEG}%H:%M:%S",
    // <MM/DD/YY@HH:MM:SS>
    r"^<%m/%d/%Exy@%H:%M:%S>",
    // MySQL compact YYMMDD HH:MM:SS
    r"%Exy%Exm%Exd  ?%H:%M:%S",
    // US full month + AM/PM: May 14, 2024 08:30:15 PM
    r"%b %d, %ExY %I:%M:%S %p",
    // ^May-14-24  8:30:15
    r"^%b-%d-%Exy %k:%M:%S",
    // Compact ISO: 20240514T083015 / 20240514 08:30:15
    r"%ExY%Exm%Exd(?:-|T|  ?)%ExH:?%ExM:?%ExS(?:[.,]%f)?(?:\s*%z)?",
    // TZ + syslog: UTC Sun Dec 04 04:47:44
    r"(?:%Z )?(?:%a )?%b %d %k:%M:%S(?:\.%f)?(?: %ExY)?",
    // Offset + syslog: +0200 Sun Dec 04 04:47:44
    r"(?:%z )?(?:%a )?%b %d %k:%M:%S(?:\.%f)?(?: %ExY)?",
    // DJB TAI64N: @4000000050606b6c2c8e12f4
    r"TAI64N",
];

/// Priority weight assigned to line-begin anchored default templates.
const LINE_BEGIN_WEIGHT: f64 = 100.0;

/// Successful match produced by [`DateDetector::match_time`].
#[derive(Debug, Clone, PartialEq)]
pub struct TimeMatch {
    /// Parsed Unix timestamp (`None` only when `{NONE}` sentinel matched).
    pub timestamp: Option<f64>,
    /// Start byte offset of matched timestamp in the input line.
    pub start: usize,
    /// End byte offset of matched timestamp in the input line.
    pub end: usize,
    /// Index of the template that matched (after any adaptive reordering).
    pub template_idx: usize,
}

/// Summary metadata for a single template (used by `fail2ban-regex` reporting).
#[derive(Debug, Clone, PartialEq)]
pub struct TemplateInfo {
    pub name: String,
    pub pattern: Option<String>,
    pub regex: String,
    pub hits: usize,
    pub weight: f64,
}

/// Adaptive date detector matching Fail2Ban 1.1.1 `DateDetector`.
#[derive(Debug, Clone)]
pub struct DateDetector {
    templates: Vec<DateTemplate>,
    default_tz: Option<i32>,
    default_tz_name: Option<String>,
    pattern: Option<String>,
    has_defaults: bool,
}

impl Default for DateDetector {
    fn default() -> Self {
        Self::with_defaults().unwrap_or_else(|_| Self::empty())
    }
}

impl DateDetector {
    /// Construct an empty [`DateDetector`] (matching upstream `DateDetector()`).
    pub fn empty() -> Self {
        Self {
            templates: Vec::new(),
            default_tz: None,
            default_tz_name: None,
            pattern: None,
            has_defaults: false,
        }
    }

    /// Construct an empty [`DateDetector`] (alias of [`DateDetector::empty`]).
    pub fn new() -> Self {
        Self::empty()
    }

    /// Construct a [`DateDetector`] pre-populated with all 31 default templates
    /// (17 line-begin anchored + 14 unanchored copies).
    pub fn with_defaults() -> Result<Self> {
        let mut dd = Self::empty();
        dd.add_default_template()?;
        Ok(dd)
    }

    /// Return configured fallback timezone offset in minutes, if set.
    pub fn default_tz(&self) -> Option<i32> {
        self.default_tz
    }

    /// Return configured fallback timezone name string, if set.
    pub fn default_tz_name(&self) -> Option<&str> {
        self.default_tz_name.as_deref()
    }

    /// Set the fallback timezone used when log timestamps omit timezone offsets.
    pub fn set_default_tz(&mut self, tz: Option<&str>) -> Result<()> {
        let parsed = validate_timezone(tz)?;
        self.default_tz = parsed;
        self.default_tz_name = tz.map(str::to_owned);
        Ok(())
    }

    /// Return the configured custom `datepattern` string (if any) and compiled
    /// primary pattern representation (matching `get datepattern`).
    pub fn date_pattern(&self) -> Option<(Option<String>, String)> {
        let pat = self.pattern.as_ref()?;
        if self.templates.len() > 2 {
            return Some((None, "Default Detectors".to_owned()));
        }
        let desc = self
            .templates
            .first()
            .map(|t| t.name.clone())
            .unwrap_or_else(|| pat.clone());
        Some((Some(pat.clone()), desc))
    }

    /// Store the custom `datepattern` specification string (e.g. from `Filter::set_date_pattern`).
    pub fn set_pattern_spec(&mut self, pattern: Option<String>) {
        self.pattern = pattern;
    }

    /// Remove all registered templates.
    pub fn clear(&mut self) {
        self.templates.clear();
        self.has_defaults = false;
    }

    /// Number of active templates.
    pub fn len(&self) -> usize {
        self.templates.len()
    }

    /// Return `true` if no templates are registered.
    pub fn is_empty(&self) -> bool {
        self.templates.is_empty()
    }

    /// Return `true` if `{NONE}` sentinel template is present.
    pub fn has_none_template(&self) -> bool {
        self.templates.iter().any(DateTemplate::is_none_sentinel)
    }

    /// Append a custom template pattern, expanding `{DEFAULT}`, `{NONE}`,
    /// `{^LN-BEG}`, and `{DATE}` pre-match expansions.
    pub fn append_template(&mut self, pattern: &str) -> Result<()> {
        for raw_line in pattern.lines() {
            let trimmed = raw_line.trim();
            if trimmed.is_empty() {
                continue;
            }
            if trimmed == "{DEFAULT}" {
                self.add_default_template()?;
                continue;
            }
            if trimmed == "{^LN-BEG}" {
                self.add_builtin_templates(true)?;
                continue;
            }
            if trimmed.contains("{DATE}") {
                self.append_date_macro_templates(raw_line)?;
                continue;
            }
            let mut tmpl = DateTemplate::from_pattern(raw_line)?;
            if tmpl.is_line_begin() {
                tmpl.weight = LINE_BEGIN_WEIGHT;
            }
            self.templates.push(tmpl);
        }
        Ok(())
    }

    /// Add all 17 upstream `DEFAULT_TEMPLATES`: 17 line-begin anchored copies
    /// (`weight = 100.0`) followed by 14 unanchored copies (`weight = 0.0`).
    /// Calling this when defaults are already loaded is a no-op.
    pub fn add_default_template(&mut self) -> Result<()> {
        self.add_builtin_templates(false)
    }

    fn add_builtin_templates(&mut self, line_begin_only: bool) -> Result<()> {
        if self.has_defaults {
            return Ok(());
        }
        let mut anchored = Vec::with_capacity(DEFAULT_TEMPLATES.len());
        let mut unanchored = Vec::with_capacity(DEFAULT_TEMPLATES.len());

        for &raw in DEFAULT_TEMPLATES {
            let already_anchored = raw.starts_with("{^LN-BEG}") || raw.starts_with('^');
            if already_anchored {
                let mut tmpl = DateTemplate::from_pattern(raw)?;
                if line_begin_only {
                    tmpl.weight = LINE_BEGIN_WEIGHT;
                    anchored.push(tmpl);
                } else {
                    unanchored.push(tmpl);
                }
            } else {
                let ln_pat = format!("{{^LN-BEG}}{raw}");
                let mut ln_tmpl = DateTemplate::from_pattern(&ln_pat)?;
                ln_tmpl.weight = LINE_BEGIN_WEIGHT;
                anchored.push(ln_tmpl);

                if !line_begin_only {
                    unanchored.push(DateTemplate::from_pattern(raw)?);
                }
            }
        }

        self.templates.extend(anchored);
        self.templates.extend(unanchored);
        self.sort_templates_stable();
        self.has_defaults = !line_begin_only;
        Ok(())
    }

    /// Expand a pattern containing `{DATE}` by pre-substituting each default template.
    fn append_date_macro_templates(&mut self, wrapper: &str) -> Result<()> {
        let mut anchored_group = Vec::new();
        let mut unanchored_group = Vec::new();

        for &raw in DEFAULT_TEMPLATES {
            // Skip TAI64N inside composite {DATE} patterns unless handled as epoch/strptime;
            // replace EPOCH with {EPOCH} so DateTemplate recognizes _f2b_epoch capture.
            let sub_body = if raw == "TAI64N" {
                continue;
            } else if raw == "EPOCH" {
                "{EPOCH}".to_owned()
            } else {
                let mut u = unbound_pattern(raw);
                if let Some(rest) = u.strip_prefix('^') {
                    u = rest.to_owned();
                }
                u
            };

            let expanded = wrapper.replace("{DATE}", &sub_body);
            let mut tmpl = DateTemplate::from_pattern(&expanded)?;
            if tmpl.is_line_begin() {
                tmpl.weight = LINE_BEGIN_WEIGHT;
                anchored_group.push(tmpl);
            } else {
                unanchored_group.push(tmpl);
            }
        }

        self.templates.extend(anchored_group);
        self.templates.extend(unanchored_group);
        Ok(())
    }

    /// Match the earliest/best timestamp in `line`, updating adaptive template ordering.
    ///
    /// Returns:
    /// - `Some(TimeMatch { timestamp: Some(ts), .. })` when a template parsed a valid date.
    /// - `Some(TimeMatch { timestamp: None, .. })` when `{NONE}` sentinel was hit.
    /// - `None` when no template matched or all regex matches failed calendar/tz validation.
    pub fn match_time(&mut self, line: &str) -> Option<TimeMatch> {
        if self.templates.is_empty() {
            return None;
        }

        let mut best: Option<(usize, f64, usize, usize)> = None;
        let len = line.len();

        for idx in 0..self.templates.len() {
            if self.templates[idx].is_none_sentinel() {
                if let Some((b_idx, ts, s, e)) = best {
                    let final_idx = self.record_hit_and_reorder(b_idx);
                    return Some(TimeMatch {
                        timestamp: Some(ts),
                        start: s,
                        end: e,
                        template_idx: final_idx,
                    });
                }
                self.templates[idx].hits += 1;
                return Some(TimeMatch {
                    timestamp: None,
                    start: 0,
                    end: 0,
                    template_idx: idx,
                });
            }

            let prev_hits = self.templates[idx].hits;
            match self.templates[idx].get_date(line, self.default_tz, 0, len) {
                Ok(None) => continue,
                Err(err) => {
                    log_msg(
                        LogLevel::TraceDebug,
                        "fail2ban.datedetector",
                        &format!("Ignore invalid date match in template #{idx}: {err}"),
                    );
                    continue;
                }
                Ok(Some((ts, s, e))) => {
                    // Warm fast-path: return immediately on previously proven template or distance 0.
                    if prev_hits > 0 || s == 0 {
                        if let Some((b_idx, b_ts, b_s, b_e)) = best
                            && b_s <= s
                        {
                            let final_idx = self.record_hit_and_reorder(b_idx);
                            return Some(TimeMatch {
                                timestamp: Some(b_ts),
                                start: b_s,
                                end: b_e,
                                template_idx: final_idx,
                            });
                        }
                        let final_idx = self.record_hit_and_reorder(idx);
                        return Some(TimeMatch {
                            timestamp: Some(ts),
                            start: s,
                            end: e,
                            template_idx: final_idx,
                        });
                    }

                    // Cold-start candidate with distance > 0: keep the earliest position on line.
                    match best {
                        Some((_, _, b_s, _)) if b_s <= s => {}
                        _ => best = Some((idx, ts, s, e)),
                    }
                }
            }
        }

        if let Some((b_idx, ts, s, e)) = best {
            let final_idx = self.record_hit_and_reorder(b_idx);
            return Some(TimeMatch {
                timestamp: Some(ts),
                start: s,
                end: e,
                template_idx: final_idx,
            });
        }
        None
    }

    /// Match and return `(timestamp, span_start, span_end)` if a concrete timestamp matched.
    pub fn get_time(&mut self, line: &str) -> Option<(f64, usize, usize)> {
        let tm = self.match_time(line)?;
        tm.timestamp.map(|ts| (ts, tm.start, tm.end))
    }

    /// Return diagnostic info (`name`, `pattern`, `regex`, `hits`, `weight`) for each template.
    pub fn templates_info(&self) -> Vec<TemplateInfo> {
        self.templates
            .iter()
            .map(|t| TemplateInfo {
                name: t.name.clone(),
                pattern: t.pattern.clone(),
                regex: t.regex.clone(),
                hits: t.hits,
                weight: t.weight,
            })
            .collect()
    }

    fn record_hit_and_reorder(&mut self, mut idx: usize) -> usize {
        self.templates[idx].hits += 1;
        while idx > 0 && self.templates[idx].score() > self.templates[idx - 1].score() {
            self.templates.swap(idx, idx - 1);
            idx -= 1;
        }
        idx
    }

    fn sort_templates_stable(&mut self) {
        self.templates
            .sort_by(|a, b| b.score().total_cmp(&a.score()));
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn default_templates_count_and_common_formats() {
        let mut dd = DateDetector::with_defaults().unwrap();
        // 17 anchored (#9,#10,#13 already anchored + 14 anchored copies) + 14 unanchored = 31.
        assert_eq!(dd.len(), 31);

        let lines = [
            "2024-05-14 08:30:15.123 +0200 sshd[1]: Failed",
            "May 14 08:30:15 server sshd[1]: Failed",
            "[Sun May 14 08:30:15 2023] [error] client 1.2.3.4",
            "192.0.2.1 - - [14/May/2024:08:30:15 +0000] \"GET /\"",
            "type=AVC msg=audit(1700000000.123:456): avc",
            "240514  8:30:15 [Note] MariaDB",
            "@4000000050606b6c2c8e12f4 qmail",
            "May 14, 2024 08:30:15 PM app: login",
            "20240514T083015Z service: ok",
            "08:30:15 bare line",
        ];

        for line in lines {
            let res = dd.get_time(line);
            assert!(res.is_some(), "failed to detect date in {line:?}");
        }
    }

    #[test]
    fn adaptive_reordering_moves_hot_unanchored_template_to_front() {
        let mut dd = DateDetector::with_defaults().unwrap();
        let line = "192.0.2.10 - - [14/May/2024:08:30:15 +0000] \"GET /\"";

        // First match: Apache CLF is initially unanchored (weight = 0.0).
        let first = dd.match_time(line).unwrap();
        assert!(first.timestamp.is_some());
        assert_eq!(&line[first.start..first.end], "14/May/2024:08:30:15 +0000");

        // After > 100 hits, its score (hits > 100) exceeds unused LINE_BEGIN templates (weight 100).
        for _ in 0..105 {
            let tm = dd.match_time(line).unwrap();
            assert!(tm.timestamp.is_some());
        }
        let fast = dd.match_time(line).unwrap();
        assert_eq!(fast.template_idx, 0);
        assert!(dd.templates_info()[0].hits >= 106);
    }

    #[test]
    fn date_macro_and_default_and_none_sentinels() {
        let mut dd = DateDetector::new();
        dd.append_template(r"^\[tag\] {DATE}").unwrap();
        assert!(!dd.is_empty());
        let line = "[tag] 2024-05-14 08:30:15 message";
        let (ts, s, e) = dd.get_time(line).unwrap();
        assert!(ts > 1_715_000_000.0);
        assert_eq!(&line[s..e], "[tag] 2024-05-14 08:30:15");

        let mut dd_none = DateDetector::new();
        dd_none.append_template("{NONE}").unwrap();
        let m = dd_none.match_time("no timestamp here").unwrap();
        assert!(m.timestamp.is_none());
        assert!(dd_none.has_none_template());

        let mut dd_def = DateDetector::new();
        dd_def.append_template("{DEFAULT}").unwrap();
        assert_eq!(dd_def.len(), 31);

        let mut anchored = DateDetector::new();
        anchored.append_template("{^LN-BEG}").unwrap();
        let line = "2012/04/09 11:53:29 [error] nginx";
        let (_, start, end) = anchored.get_time(line).unwrap();
        assert_eq!(&line[start..end], "2012/04/09 11:53:29");
        assert!(
            anchored
                .get_time("prefix 2012/04/09 11:53:29 [error]")
                .is_none()
        );
    }

    #[test]
    fn default_tz_applied_when_line_has_no_offset() {
        let mut dd = DateDetector::with_defaults().unwrap();
        dd.set_default_tz(Some("+0200")).unwrap();
        assert_eq!(dd.default_tz(), Some(120));

        let mut dd_utc = DateDetector::with_defaults().unwrap();
        dd_utc.set_default_tz(Some("UTC")).unwrap();
        let line = "2024-05-14 08:30:15 message";
        let (t_plus2, _, _) = dd.get_time(line).unwrap();
        let (t_utc, _, _) = dd_utc.get_time(line).unwrap();
        assert!((t_utc - t_plus2 - 7200.0).abs() < 1e-6);
    }
}
