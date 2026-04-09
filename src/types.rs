use std::collections::HashMap;
use serde::{Deserialize, Serialize};

/// A single secret-key finding within a scanned file.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Finding {
    /// Sequential ID within this scan run, e.g. "f-001".
    pub id: String,
    /// Stable fingerprint derived from pattern_id + file + match_body.
    /// Survives line-number shifts caused by inserting code above the secret.
    pub fingerprint: String,
    /// Provider slug in lowercase, e.g. "openai", "anthropic".
    pub provider: String,
    /// Path relative to scan_root.
    pub file: String,
    /// 1-indexed line number.
    pub line: usize,
    /// 1-indexed column where the match starts.
    pub column: usize,
    /// Matched text with the key body replaced by ***REDACTED***.
    #[serde(rename = "match")]
    pub match_text: String,
    /// Stable pattern identifier, e.g. "openai-project-key-v2".
    pub pattern_id: String,
    /// Severity: "critical", "high", or "medium".
    pub severity: String,
    /// Shannon entropy of the matched key body (bits per character).
    pub entropy: f64,
    /// Provider-specific remediation guidance.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
    // ── v2.1 enrichment fields ────────────────────────────────────────────────
    /// Offline or network validation status: "likely-valid", "test-key",
    /// "network-valid", "network-invalid".  Absent when validation is not run.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validation_status: Option<String>,
    /// ISO-8601 UTC timestamp when this fingerprint first appeared in a baseline.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_seen: Option<String>,
    /// ISO-8601 UTC timestamp of the most recent scan that found this fingerprint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_seen: Option<String>,
    /// Code owner(s) from CODEOWNERS for the file containing this finding.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    /// Author of the last commit that touched this line (git blame).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_author: Option<String>,
    /// How this finding was suppressed, e.g. "baseline:fp-abc123" or "allowlist:rule-id".
    /// Only set on findings in `baselined_findings` or reported suppressed lists.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suppression_provenance: Option<String>,
    /// Raw credential body for in-process network validation.
    /// Never serialised to JSON/SARIF/text output.
    #[serde(skip)]
    pub secret_body: Option<String>,
}

impl Finding {
    /// Construct a finding with defaults for new v2 fields.
    ///
    /// `fingerprint` is computed from `pattern_id`, `file`, and `match_text`
    /// (using `match_text` as a proxy for the credential body).  This helper
    /// is intended for tests; production code in `main.rs` initialises
    /// `Finding` directly from `RawFinding` with the real body.
    ///
    /// `severity` defaults to `"critical"`.  `remediation` defaults to `None`.
    #[allow(dead_code)]
    pub fn new(
        seq: usize,
        provider: &str,
        file: &str,
        line: usize,
        column: usize,
        match_text: String,
        pattern_id: &str,
        entropy: f64,
    ) -> Self {
        // Use match_text as the body proxy so tests can control fingerprint
        // uniqueness by varying match_text.
        let fingerprint = crate::fingerprint::compute(pattern_id, file, &match_text);
        Self {
            id: format!("f-{seq:03}"),
            fingerprint,
            provider: provider.to_string(),
            file: file.to_string(),
            line,
            column,
            match_text,
            pattern_id: pattern_id.to_string(),
            severity: "critical".to_string(),
            entropy,
            remediation: None,
            validation_status: None,
            first_seen: None,
            last_seen: None,
            owner: None,
            last_author: None,
            suppression_provenance: None,
            secret_body: None,
        }
    }
}

/// Scan performance and coverage metrics included in every report.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct ScanMetrics {
    /// Wall-clock duration of the scan in milliseconds.
    pub scan_duration_ms: u64,
    /// Files that were skipped (too large, unreadable, binary).
    pub files_skipped: usize,
    /// Total raw pattern matches before entropy filtering.
    pub total_raw_matches: usize,
    /// High-confidence findings before allowlist/baseline filtering.
    pub high_confidence_count: usize,
    /// Low-confidence findings (below entropy threshold).
    pub low_confidence_count: usize,
    /// Findings suppressed by the allowlist.
    pub suppressed_count: usize,
    /// Findings suppressed by the baseline.
    pub baselined_count: usize,
    /// Jupyter notebook files scanned (code cells extracted).
    #[serde(default)]
    pub notebooks_scanned: usize,
    /// Archive files scanned (zip/tar contents extracted).
    #[serde(default)]
    pub archives_scanned: usize,
    /// Files skipped because the hash cache confirmed they are unchanged.
    #[serde(default)]
    pub cached_files_skipped: usize,
}

/// Summary block included in every report.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct Summary {
    pub total_findings: usize,
    pub by_provider: HashMap<String, usize>,
    pub files_with_findings: usize,
}

impl Summary {
    pub fn from_findings(findings: &[Finding]) -> Self {
        let mut by_provider: HashMap<String, usize> = HashMap::new();
        for f in findings {
            *by_provider.entry(f.provider.clone()).or_insert(0) += 1;
        }
        let files_with_findings = {
            let mut files: Vec<&str> = findings.iter().map(|f| f.file.as_str()).collect();
            files.sort_unstable();
            files.dedup();
            files.len()
        };
        Self {
            total_findings: findings.len(),
            by_provider,
            files_with_findings,
        }
    }
}

/// Top-level JSON report structure written to stdout or --output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub scan_id: String,
    pub tool: String,
    pub version: String,
    pub timestamp: String,
    pub scan_root: String,
    pub files_scanned: usize,
    /// High-confidence findings not suppressed by allowlist or baseline.
    pub findings: Vec<Finding>,
    /// Pattern matches below the entropy threshold — not exit-1 triggers.
    pub low_confidence_findings: Vec<Finding>,
    /// High-confidence findings suppressed by `--baseline`.
    #[serde(default)]
    pub baselined_findings: Vec<Finding>,
    pub summary: Summary,
    /// Scan performance and coverage metrics.
    pub metrics: ScanMetrics,
}

/// Output format requested by the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Json,
    Sarif,
    Text,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finding_id_format() {
        let f = Finding::new(1, "openai", "src/main.py", 10, 5, "sk-***REDACTED***".into(), "openai-legacy-key-v1", 4.5);
        assert_eq!(f.id, "f-001");
        assert_eq!(f.severity, "critical");
    }

    #[test]
    fn finding_id_pads_to_three_digits() {
        let f = Finding::new(42, "anthropic", "a.py", 1, 1, "sk-ant-***REDACTED***".into(), "anthropic-api-key-v1", 4.8);
        assert_eq!(f.id, "f-042");
    }

    #[test]
    fn finding_fingerprint_is_populated() {
        let f = Finding::new(1, "openai", "src/config.py", 12, 1, "sk-***REDACTED***".into(), "openai-project-key-v2", 4.5);
        assert!(f.fingerprint.starts_with("fp-"));
        assert_eq!(f.fingerprint.len(), 19);
    }

    #[test]
    fn finding_fingerprint_stable_for_same_inputs() {
        let f1 = Finding::new(1, "openai", "src/config.py", 10, 1, "sk-secretbody".into(), "openai-project-key-v2", 4.5);
        let f2 = Finding::new(2, "openai", "src/config.py", 42, 5, "sk-secretbody".into(), "openai-project-key-v2", 3.9);
        // Same pattern_id, file, and body → same fingerprint regardless of seq/line/column/entropy
        assert_eq!(f1.fingerprint, f2.fingerprint, "fingerprint must survive line-number shifts");
    }

    #[test]
    fn summary_empty_findings() {
        let s = Summary::from_findings(&[]);
        assert_eq!(s.total_findings, 0);
        assert_eq!(s.files_with_findings, 0);
        assert!(s.by_provider.is_empty());
    }

    #[test]
    fn summary_aggregates_correctly() {
        let findings = vec![
            Finding::new(1, "openai", "a.py", 1, 1, "".into(), "openai-legacy-key-v1", 4.0),
            Finding::new(2, "openai", "b.py", 2, 1, "".into(), "openai-legacy-key-v1", 4.0),
            Finding::new(3, "anthropic", "a.py", 3, 1, "".into(), "anthropic-api-key-v1", 4.5),
        ];
        let s = Summary::from_findings(&findings);
        assert_eq!(s.total_findings, 3);
        assert_eq!(*s.by_provider.get("openai").unwrap(), 2);
        assert_eq!(*s.by_provider.get("anthropic").unwrap(), 1);
        assert_eq!(s.files_with_findings, 2);
    }

    #[test]
    fn scan_metrics_default_all_zero() {
        let m = ScanMetrics::default();
        assert_eq!(m.scan_duration_ms, 0);
        assert_eq!(m.files_skipped, 0);
        assert_eq!(m.suppressed_count, 0);
        assert_eq!(m.baselined_count, 0);
    }
}
