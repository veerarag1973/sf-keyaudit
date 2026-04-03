use crate::error::AuditError;
use crate::types::Report;

/// Serialise a [`Report`] to a pretty-printed JSON string.
pub fn render(report: &Report) -> Result<String, AuditError> {
    serde_json::to_string_pretty(report).map_err(AuditError::Serialization)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Finding, Report, Summary};
    use std::collections::HashMap;

    fn sample_report() -> Report {
        Report {
            scan_id: "test-scan-id".into(),
            tool: "sf-keyaudit".into(),
            version: "1.0.0".into(),
            timestamp: "2026-04-03T10:00:00Z".into(),
            scan_root: "/home/app".into(),
            files_scanned: 42,
            findings: vec![Finding::new(
                1,
                "openai",
                "src/config.py",
                10,
                5,
                "sk-proj-***REDACTED***".into(),
                "openai-project-key-v2",
                4.87,
            )],
            low_confidence_findings: vec![],
            summary: Summary {
                total_findings: 1,
                by_provider: {
                    let mut m = HashMap::new();
                    m.insert("openai".into(), 1);
                    m
                },
                files_with_findings: 1,
            },
        }
    }

    #[test]
    fn render_produces_valid_json() {
        let report = sample_report();
        let json = render(&report).unwrap();
        let val: serde_json::Value = serde_json::from_str(&json).expect("must be valid JSON");
        assert!(val.is_object());
    }

    #[test]
    fn json_contains_all_top_level_fields() {
        let report = sample_report();
        let json = render(&report).unwrap();
        let val: serde_json::Value = serde_json::from_str(&json).unwrap();
        for field in &[
            "scan_id", "tool", "version", "timestamp", "scan_root",
            "files_scanned", "findings", "low_confidence_findings", "summary",
        ] {
            assert!(val.get(field).is_some(), "missing field: {field}");
        }
    }

    #[test]
    fn findings_match_field_is_redacted() {
        let report = sample_report();
        let json = render(&report).unwrap();
        // The raw key body must not appear in the output
        assert!(!json.contains("sk-proj-REAL_KEY_VALUE"));
        assert!(json.contains("***REDACTED***"));
    }

    #[test]
    fn tool_name_is_correct() {
        let report = sample_report();
        let json = render(&report).unwrap();
        assert!(json.contains(r#""tool": "sf-keyaudit""#));
    }

    #[test]
    fn summary_by_provider_present() {
        let report = sample_report();
        let json = render(&report).unwrap();
        assert!(json.contains("by_provider"));
        assert!(json.contains("openai"));
    }

    #[test]
    fn empty_findings_produces_empty_array() {
        let mut report = sample_report();
        report.findings = vec![];
        report.summary = Summary::default();
        let json = render(&report).unwrap();
        let val: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(val["findings"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn severity_is_always_critical() {
        let report = sample_report();
        let json = render(&report).unwrap();
        let val: serde_json::Value = serde_json::from_str(&json).unwrap();
        let findings = val["findings"].as_array().unwrap();
        for f in findings {
            assert_eq!(f["severity"].as_str().unwrap(), "critical");
        }
    }
}
