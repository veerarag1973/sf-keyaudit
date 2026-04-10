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
            version: "2.0.0".into(),
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
            baselined_findings: vec![],
            summary: Summary {
                total_findings: 1,
                by_provider: {
                    let mut m = HashMap::new();
                    m.insert("openai".into(), 1);
                    m
                },
                files_with_findings: 1,
            },
            metrics: crate::types::ScanMetrics::default(),
            policy_violations: vec![],
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
            let sev = f["severity"].as_str().unwrap();
            assert!(
                ["critical", "high", "medium"].contains(&sev),
                "severity must be critical/high/medium, got: {sev}"
            );
        }
    }

    #[test]
    fn findings_have_fingerprint_field() {
        let report = sample_report();
        let json = render(&report).unwrap();
        let val: serde_json::Value = serde_json::from_str(&json).unwrap();
        let f = &val["findings"][0];
        let fp = f["fingerprint"].as_str().unwrap();
        assert!(fp.starts_with("fp-"), "fingerprint must start with 'fp-': {fp}");
        assert_eq!(fp.len(), 19, "fingerprint must be 19 chars: {fp}");
    }

    #[test]
    fn report_has_metrics_field() {
        let report = sample_report();
        let json = render(&report).unwrap();
        let val: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(val.get("metrics").is_some(), "report must have 'metrics' field");
    }

    #[test]
    fn metrics_contains_expected_fields() {
        let report = sample_report();
        let json = render(&report).unwrap();
        let val: serde_json::Value = serde_json::from_str(&json).unwrap();
        let metrics = &val["metrics"];
        assert!(metrics.get("scan_duration_ms").is_some());
        assert!(metrics.get("files_skipped").is_some());
        assert!(metrics.get("suppressed_count").is_some());
        assert!(metrics.get("baselined_count").is_some());
    }

    #[test]
    fn policy_violations_absent_in_json_when_empty() {
        // When policy_violations is an empty Vec, the field must be omitted
        // from the JSON output because of #[serde(skip_serializing_if = "Vec::is_empty")].
        let report = sample_report(); // policy_violations = vec![]
        let json = render(&report).unwrap();
        assert!(!json.contains("policy_violations"),
            "policy_violations must be absent when empty");
    }

    #[test]
    fn policy_violations_present_in_json_when_non_empty() {
        use crate::types::{PolicyDecision, PolicyViolation};
        let mut report = sample_report();
        let fp = report.findings[0].fingerprint.clone();
        report.policy_violations = vec![PolicyViolation {
            fingerprint:   fp,
            rule:          "block-critical".to_string(),
            decision:      PolicyDecision::Block,
            justification: "severity=critical exceeds threshold".to_string(),
        }];
        let json = render(&report).unwrap();
        assert!(json.contains("policy_violations"),
            "policy_violations must be present when non-empty");
        assert!(json.contains("block-critical"));
    }
}
