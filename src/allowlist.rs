//! Allowlist loader and matcher.
//!
//! The allowlist suppresses known-safe findings without disabling the scan.
//! Every entry must declare `pattern_id`, `file`, `line`, and `reason`.
//! An optional `expires` date causes the entry to be ignored after that date.

use crate::error::AuditError;
use crate::types::Finding;
use chrono::{NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// One entry in the `.sfkeyaudit-allow.yaml` file.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AllowEntry {
    pub pattern_id: String,
    /// Path relative to scan_root, matching `Finding.file`.
    pub file: String,
    /// 1-indexed line number matching `Finding.line`.
    pub line: usize,
    /// 1-indexed column number matching `Finding.column`.  `None` matches any
    /// column on the given line (backwards-compatible with existing allowlists).
    #[serde(default)]
    pub column: Option<usize>,
    /// Required human-readable justification.
    pub reason: String,
    /// Optional ISO-8601 date (YYYY-MM-DD).  Entry ignored after this date.
    pub expires: Option<String>,
}

/// Top-level structure of the allowlist YAML file.
#[derive(Debug, Deserialize)]
struct AllowlistFile {
    allowlist: Vec<AllowEntry>,
}

/// Loaded and validated allowlist, ready for matching.
#[derive(Debug, Default, Clone)]
pub struct Allowlist {
    entries: Vec<AllowEntry>,
}

/// Outcome of allowlist validation.
#[derive(Debug, PartialEq)]
pub enum AllowlistWarning {
    /// An entry's expiry date has passed.
    Expired { pattern_id: String, file: String, line: usize },
    /// An entry did not match any finding — likely a stale entry.
    Unmatched { pattern_id: String, file: String, line: usize },
}

impl Allowlist {
    /// Load from a YAML file.  Returns an error if the file is malformed or
    /// any entry is missing a `reason`.
    pub fn load(path: &Path) -> Result<Self, AuditError> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| AuditError::AllowlistMalformed(format!("cannot read {}: {e}", path.display())))?;
        Self::parse(&content)
    }

    /// Parse from a YAML string (useful in tests).
    pub fn parse(yaml: &str) -> Result<Self, AuditError> {
        let file: AllowlistFile = serde_yaml::from_str(yaml)
            .map_err(|e| AuditError::AllowlistMalformed(e.to_string()))?;

        for entry in &file.allowlist {
            if entry.reason.trim().is_empty() {
                return Err(AuditError::AllowlistMissingReason {
                    file: entry.file.clone(),
                    line: entry.line,
                });
            }
        }

        Ok(Self { entries: file.allowlist })
    }

    /// Returns an empty allowlist — used when no `--allowlist` flag is passed.
    pub fn empty() -> Self {
        Self { entries: vec![] }
    }

    /// Apply the allowlist to a set of findings.
    ///
    /// Returns:
    /// - `suppressed`: findings that were suppressed by an active entry.
    /// - `active`: findings that passed through (not suppressed).
    /// - `warnings`: expired entries and unmatched entries.
    pub fn apply(
        &self,
        findings: &[Finding],
        today: NaiveDate,
    ) -> (Vec<Finding>, Vec<Finding>, Vec<AllowlistWarning>) {
        let mut warnings = Vec::new();

        // Partition entries into expired vs active.
        let active_entries: Vec<&AllowEntry> = self
            .entries
            .iter()
            .filter(|e| {
                if let Some(exp) = &e.expires {
                    match NaiveDate::parse_from_str(exp, "%Y-%m-%d") {
                        Ok(d) if d < today => {
                            warnings.push(AllowlistWarning::Expired {
                                pattern_id: e.pattern_id.clone(),
                                file: e.file.clone(),
                                line: e.line,
                            });
                            false
                        }
                        Err(_) => {
                            // Treat unparseable date as no expiry (warn separately via stderr in main)
                            true
                        }
                        _ => true,
                    }
                } else {
                    true
                }
            })
            .collect();

        let mut suppressed = Vec::new();
        let mut active = Vec::new();
        let mut matched_entries: Vec<bool> = vec![false; active_entries.len()];

        for finding in findings {
            let mut was_suppressed = false;
            for (i, entry) in active_entries.iter().enumerate() {
                // column is optional — None means "any column on this line"
                // (backwards-compatible with older allowlists that omit it).
                let column_matches = entry
                    .column
                    .map(|c| c == finding.column)
                    .unwrap_or(true);
                if entry.pattern_id == finding.pattern_id
                    && entry.file == finding.file
                    && entry.line == finding.line
                    && column_matches
                {
                    matched_entries[i] = true;
                    was_suppressed = true;
                    break;
                }
            }
            if was_suppressed {
                suppressed.push(finding.clone());
            } else {
                active.push(finding.clone());
            }
        }

        // Warn about allowlist entries that matched nothing.
        for (i, entry) in active_entries.iter().enumerate() {
            if !matched_entries[i] {
                warnings.push(AllowlistWarning::Unmatched {
                    pattern_id: entry.pattern_id.clone(),
                    file: entry.file.clone(),
                    line: entry.line,
                });
            }
        }

        (suppressed, active, warnings)
    }

    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Return today's date in UTC — injectable in tests via the parameter on `apply`.
pub fn today_utc() -> NaiveDate {
    Utc::now().date_naive()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Finding;

    fn make_finding(pattern_id: &str, file: &str, line: usize) -> Finding {
        Finding::new(1, "openai", file, line, 1, "sk-***REDACTED***".into(), pattern_id, 4.5)
    }

    fn today() -> NaiveDate {
        NaiveDate::from_ymd_opt(2026, 4, 3).unwrap()
    }

    fn future() -> NaiveDate {
        NaiveDate::from_ymd_opt(2026, 4, 4).unwrap()
    }

    fn past() -> NaiveDate {
        NaiveDate::from_ymd_opt(2026, 4, 2).unwrap()
    }

    // ── parse ───────────────────────────────────────────────────────────────

    #[test]
    fn parse_valid_allowlist() {
        let yaml = r#"
allowlist:
  - pattern_id: openai-legacy-key-v1
    file: tests/fixtures/mock_keys.py
    line: 14
    reason: "Test fixture — not a live key"
"#;
        let al = Allowlist::parse(yaml).unwrap();
        assert_eq!(al.entries.len(), 1);
        assert_eq!(al.entries[0].pattern_id, "openai-legacy-key-v1");
    }

    #[test]
    fn parse_entry_with_expiry() {
        let yaml = r#"
allowlist:
  - pattern_id: openai-legacy-key-v1
    file: tests/mock.py
    line: 1
    reason: "CI mock"
    expires: "2026-07-01"
"#;
        let al = Allowlist::parse(yaml).unwrap();
        assert_eq!(al.entries[0].expires, Some("2026-07-01".to_string()));
    }

    #[test]
    fn parse_fails_on_missing_reason() {
        let yaml = r#"
allowlist:
  - pattern_id: openai-legacy-key-v1
    file: tests/fixtures/mock.py
    line: 5
    reason: ""
"#;
        let err = Allowlist::parse(yaml);
        assert!(err.is_err());
        let msg = err.unwrap_err().to_string();
        assert!(msg.contains("reason") || msg.contains("missing"), "got: {msg}");
    }

    #[test]
    fn parse_fails_on_malformed_yaml() {
        let err = Allowlist::parse("not: valid: yaml: [[[");
        assert!(err.is_err());
    }

    #[test]
    fn empty_allowlist_parses() {
        let yaml = "allowlist: []\n";
        let al = Allowlist::parse(yaml).unwrap();
        assert!(al.is_empty());
    }

    // ── apply — suppression ─────────────────────────────────────────────────

    #[test]
    fn suppresses_matching_finding() {
        let yaml = r#"
allowlist:
  - pattern_id: openai-legacy-key-v1
    file: tests/mock.py
    line: 14
    reason: "test"
"#;
        let al = Allowlist::parse(yaml).unwrap();
        let f = make_finding("openai-legacy-key-v1", "tests/mock.py", 14);
        let (suppressed, active, warns) = al.apply(&[f], today());
        assert_eq!(suppressed.len(), 1);
        assert_eq!(active.len(), 0);
        assert!(warns.is_empty());
    }

    #[test]
    fn does_not_suppress_wrong_pattern_id() {
        let yaml = r#"
allowlist:
  - pattern_id: anthropic-api-key-v1
    file: tests/mock.py
    line: 14
    reason: "test"
"#;
        let al = Allowlist::parse(yaml).unwrap();
        let f = make_finding("openai-legacy-key-v1", "tests/mock.py", 14);
        let (suppressed, active, _warns) = al.apply(&[f], today());
        assert_eq!(suppressed.len(), 0);
        assert_eq!(active.len(), 1);
    }

    #[test]
    fn does_not_suppress_wrong_line() {
        let yaml = r#"
allowlist:
  - pattern_id: openai-legacy-key-v1
    file: tests/mock.py
    line: 99
    reason: "test"
"#;
        let al = Allowlist::parse(yaml).unwrap();
        let f = make_finding("openai-legacy-key-v1", "tests/mock.py", 14);
        let (_, active, _) = al.apply(&[f], today());
        assert_eq!(active.len(), 1);
    }

    // ── apply — expiry ──────────────────────────────────────────────────────

    #[test]
    fn expired_entry_does_not_suppress() {
        let yaml = r#"
allowlist:
  - pattern_id: openai-legacy-key-v1
    file: tests/mock.py
    line: 14
    reason: "test"
    expires: "2026-04-01"
"#;
        let al = Allowlist::parse(yaml).unwrap();
        let f = make_finding("openai-legacy-key-v1", "tests/mock.py", 14);
        // scan date is 2026-04-03, entry expired 2026-04-01
        let (_, active, warns) = al.apply(&[f], today());
        assert_eq!(active.len(), 1, "expired entry must not suppress");
        assert!(warns.iter().any(|w| matches!(w, AllowlistWarning::Expired { .. })));
    }

    #[test]
    fn future_expiry_still_suppresses() {
        let yaml = r#"
allowlist:
  - pattern_id: openai-legacy-key-v1
    file: tests/mock.py
    line: 14
    reason: "test"
    expires: "2027-01-01"
"#;
        let al = Allowlist::parse(yaml).unwrap();
        let f = make_finding("openai-legacy-key-v1", "tests/mock.py", 14);
        let (suppressed, _, warns) = al.apply(&[f], today());
        assert_eq!(suppressed.len(), 1);
        assert!(!warns.iter().any(|w| matches!(w, AllowlistWarning::Expired { .. })));
    }

    // ── apply — unmatched entries ────────────────────────────────────────────

    #[test]
    fn unmatched_entry_produces_warning() {
        let yaml = r#"
allowlist:
  - pattern_id: openai-legacy-key-v1
    file: deleted/file.py
    line: 5
    reason: "stale entry"
"#;
        let al = Allowlist::parse(yaml).unwrap();
        // No findings at all
        let (_, _, warns) = al.apply(&[], today());
        assert!(warns.iter().any(|w| matches!(w, AllowlistWarning::Unmatched { .. })));
    }

    #[test]
    fn empty_allowlist_produces_no_warnings() {
        let al = Allowlist::empty();
        let f = make_finding("openai-legacy-key-v1", "a.py", 1);
        let (_, active, warns) = al.apply(&[f], today());
        assert_eq!(active.len(), 1);
        assert!(warns.is_empty());
    }

    // suppress with today == expiry date (boundary: not yet expired)
    #[test]
    fn entry_not_yet_expired_on_expiry_day() {
        let yaml = r#"
allowlist:
  - pattern_id: openai-legacy-key-v1
    file: tests/mock.py
    line: 14
    reason: "test"
    expires: "2026-04-03"
"#;
        // today IS the expiry date — entry is still valid (expires on the date, i.e. expired strictly before)
        let al = Allowlist::parse(yaml).unwrap();
        let f = make_finding("openai-legacy-key-v1", "tests/mock.py", 14);
        let (suppressed, _, _) = al.apply(&[f], today());
        // today == expires date: the spec says "current date is past the expiry"
        // i.e. d < today means expired; d == today means still valid
        assert_eq!(suppressed.len(), 1, "entry should still suppress on its expiry date");
    }

    #[test]
    fn entry_expired_day_after_expiry() {
        let yaml = r#"
allowlist:
  - pattern_id: openai-legacy-key-v1
    file: tests/mock.py
    line: 14
    reason: "test"
    expires: "2026-04-02"
"#;
        let al = Allowlist::parse(yaml).unwrap();
        let f = make_finding("openai-legacy-key-v1", "tests/mock.py", 14);
        let (suppressed, _active, _) = al.apply(&[f], today()); // today = 2026-04-03 > 2026-04-02
        assert_eq!(suppressed.len(), 0);
    }

    // load from filesystem
    #[test]
    fn load_from_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".sfkeyaudit-allow.yaml");
        std::fs::write(&path, b"allowlist:\n  - pattern_id: openai-legacy-key-v1\n    file: a.py\n    line: 1\n    reason: test\n").unwrap();
        let al = Allowlist::load(&path).unwrap();
        assert_eq!(al.entries.len(), 1);
    }

    #[test]
    fn load_missing_file_returns_error() {
        let err = Allowlist::load(Path::new("/nonexistent/.sfkeyaudit-allow.yaml"));
        assert!(err.is_err());
    }

    // future vs past dates for context
    #[test]
    fn future_date_is_after_today() {
        assert!(future() > today());
    }

    #[test]
    fn past_date_is_before_today() {
        assert!(past() < today());
    }

    #[test]
    fn unparseable_expiry_date_treats_entry_as_active() {
        // When the expires field cannot be parsed, the entry should still suppress
        let yaml = r#"
allowlist:
  - pattern_id: openai-legacy-key-v1
    file: src/main.py
    line: 1
    reason: "test"
    expires: "not-a-date"
"#;
        let al = Allowlist::parse(yaml).unwrap();
        let f = make_finding("openai-legacy-key-v1", "src/main.py", 1);
        let (suppressed, _active, _warns) = al.apply(&[f], today());
        // Unparseable date → treated as no expiry → still suppresses
        assert_eq!(suppressed.len(), 1);
    }
}
