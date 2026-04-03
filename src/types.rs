use std::collections::HashMap;
use serde::{Deserialize, Serialize};

/// A single secret-key finding within a scanned file.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Finding {
    /// Sequential ID within this scan run, e.g. "f-001".
    pub id: String,
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
    /// Always "critical" in v1.0.
    pub severity: String,
    /// Shannon entropy of the matched key body (bits per character).
    pub entropy: f64,
}

impl Finding {
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
        Self {
            id: format!("f-{:03}", seq),
            provider: provider.to_string(),
            file: file.to_string(),
            line,
            column,
            match_text,
            pattern_id: pattern_id.to_string(),
            severity: "critical".to_string(),
            entropy,
        }
    }
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
    pub findings: Vec<Finding>,
    /// Matches where entropy is below the threshold — not exit-1 triggers.
    pub low_confidence_findings: Vec<Finding>,
    pub summary: Summary,
}

/// Output format requested by the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Json,
    Sarif,
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
        // a.py and b.py → 2 distinct files
        assert_eq!(s.files_with_findings, 2);
    }
}
