//! SARIF 2.1.0 output for IDE and GitHub Code Scanning integration.
//!
//! Reference: <https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html>

use crate::error::AuditError;
use crate::types::Report;
use serde_json::{json, Value};

/// Render a [`Report`] as a SARIF 2.1.0 JSON string.
pub fn render(report: &Report) -> Result<String, AuditError> {
    let rules: Vec<Value> = collect_rules(report);
    let mut results: Vec<Value> = report
        .findings
        .iter()
        .map(|f| finding_to_sarif_result(f, &report.scan_root))
        .collect();

    // Baselined findings are emitted as suppressed results so that SARIF
    // consumers (e.g. GitHub Code Scanning) can track them without raising alerts.
    let suppressed: Vec<Value> = report
        .baselined_findings
        .iter()
        .map(|f| finding_to_sarif_result_suppressed(f, &report.scan_root))
        .collect();
    results.extend(suppressed);

    let sarif = json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "sf-keyaudit",
                        "version": report.version,
                        "informationUri": "https://getspanforge.com",
                        "rules": rules
                    }
                },
                "results": results,
                "newlineSequences": ["\r\n", "\n"],
                "properties": {
                    "scanRoot": report.scan_root,
                    "filesScanned": report.files_scanned,
                    "scanId": report.scan_id
                }
            }
        ]
    });

    serde_json::to_string_pretty(&sarif).map_err(AuditError::Serialization)
}

fn collect_rules(report: &Report) -> Vec<Value> {
    // Deduplicate pattern_ids across findings and low_confidence_findings.
    let mut seen = std::collections::HashSet::new();
    let mut rules = Vec::new();

    for f in report.findings.iter().chain(report.low_confidence_findings.iter()).chain(report.baselined_findings.iter()) {
        if seen.insert(f.pattern_id.clone()) {
            let help_text = if let Some(ref rem) = f.remediation {
                format!("Revoke and rotate the {} credential immediately. {}", f.provider, rem)
            } else {
                format!(
                    "An exposed {} API key was detected (pattern: {}). \
                     Remove the key and rotate it immediately.",
                    f.provider, f.pattern_id
                )
            };
            rules.push(json!({
                "id": f.pattern_id,
                "name": f.pattern_id,
                "shortDescription": {
                    "text": format!("Exposed {} API key detected", f.provider)
                },
                "fullDescription": {
                    "text": format!(
                        "An exposed {} API key was detected (pattern: {}).",
                        f.provider, f.pattern_id
                    )
                },
                "help": {
                    "text": help_text
                },
                "helpUri": "https://getspanforge.com/docs/sf-keyaudit",
                "defaultConfiguration": {
                    "level": severity_to_sarif_level(&f.severity)
                },
                "properties": {
                    "provider": f.provider,
                    "severity": f.severity,
                    "tags": ["security", "api-key", "credentials"]
                }
            }));
        }
    }
    rules
}

fn severity_to_sarif_level(severity: &str) -> &'static str {
    match severity {
        "medium" => "warning",
        "high" | "critical" => "error",
        _ => "error",
    }
}

fn finding_to_sarif_result(
    f: &crate::types::Finding,
    scan_root: &str,
) -> Value {
    // SARIF uses 0-indexed lines/columns in the physicalLocation — but the
    // spec-recommended region uses 1-indexed.  We follow the convention of
    // most SARIF producers and use 1-indexed here (GitHub Code Scanning expects it).
    let uri = format!(
        "{}",
        std::path::Path::new(scan_root)
            .join(&f.file)
            .display()
    );

    let mut properties = serde_json::json!({
        "provider": f.provider,
        "patternId": f.pattern_id,
        "entropy": f.entropy,
        "severity": f.severity,
        "fingerprint": f.fingerprint
    });
    if let Some(ref vs) = f.validation_status {
        properties["validationStatus"] = serde_json::json!(vs);
    }
    if let Some(ref owner) = f.owner {
        properties["owner"] = serde_json::json!(owner);
    }
    if let Some(ref author) = f.last_author {
        properties["lastAuthor"] = serde_json::json!(author);
    }
    if let Some(ref first) = f.first_seen {
        properties["firstSeen"] = serde_json::json!(first);
    }
    if let Some(ref last) = f.last_seen {
        properties["lastSeen"] = serde_json::json!(last);
    }

    json!({
        "ruleId": f.pattern_id,
        "level": severity_to_sarif_level(&f.severity),
        "message": {
            "text": format!(
                "Exposed {} API key found at {} (line {}). Match: {}",
                f.provider, f.file, f.line, f.match_text
            )
        },
        "fingerprints": {
            "sfKeyaudit/v1": f.fingerprint
        },
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": uri,
                        "uriBaseId": "%SRCROOT%"
                    },
                    "region": {
                        "startLine": f.line,
                        "startColumn": f.column,
                        "endLine": f.line
                    }
                }
            }
        ],
        "properties": properties
    })
}

/// Build a SARIF result for a baselined (suppressed) finding.
///
/// The result uses `"level": "none"` with a `suppressions` array so that
/// consumers like GitHub Code Scanning show the finding as "dismissed".
fn finding_to_sarif_result_suppressed(
    f: &crate::types::Finding,
    scan_root: &str,
) -> Value {
    let uri = format!(
        "{}",
        std::path::Path::new(scan_root)
            .join(&f.file)
            .display()
    );
    let suppression_kind = f
        .suppression_provenance
        .as_deref()
        .unwrap_or("baseline");
    json!({
        "ruleId": f.pattern_id,
        "level": "none",
        "message": {
            "text": format!(
                "[Baselined] Exposed {} API key at {} (line {}).",
                f.provider, f.file, f.line
            )
        },
        "fingerprints": {
            "sfKeyaudit/v1": f.fingerprint
        },
        "suppressions": [
            {
                "kind": "inSource",
                "status": "accepted",
                "justification": format!("suppressed by {}", suppression_kind)
            }
        ],
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": uri,
                        "uriBaseId": "%SRCROOT%"
                    },
                    "region": {
                        "startLine": f.line,
                        "startColumn": f.column,
                        "endLine": f.line
                    }
                }
            }
        ],
        "properties": {
            "provider": f.provider,
            "patternId": f.pattern_id,
            "entropy": f.entropy,
            "severity": f.severity,
            "fingerprint": f.fingerprint
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Finding, Report, Summary};
    use std::collections::HashMap;

    fn sample_report() -> Report {
        Report {
            scan_id: "sarif-test-id".into(),
            tool: "sf-keyaudit".into(),
            version: "2.0.0".into(),
            timestamp: "2026-04-03T10:00:00Z".into(),
            scan_root: "/home/app".into(),
            files_scanned: 10,
            findings: vec![Finding::new(
                1,
                "openai",
                "src/config.py",
                42,
                14,
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
        }
    }

    #[test]
    fn renders_valid_sarif_json() {
        let report = sample_report();
        let sarif = render(&report).unwrap();
        let val: serde_json::Value = serde_json::from_str(&sarif).expect("must be valid JSON");
        assert!(val.is_object());
    }

    #[test]
    fn sarif_version_is_correct() {
        let report = sample_report();
        let sarif = render(&report).unwrap();
        let val: serde_json::Value = serde_json::from_str(&sarif).unwrap();
        assert_eq!(val["version"].as_str().unwrap(), "2.1.0");
    }

    #[test]
    fn sarif_schema_url_present() {
        let report = sample_report();
        let sarif = render(&report).unwrap();
        assert!(sarif.contains("json.schemastore.org/sarif-2.1.0.json"));
    }

    #[test]
    fn sarif_has_runs_array() {
        let report = sample_report();
        let sarif = render(&report).unwrap();
        let val: serde_json::Value = serde_json::from_str(&sarif).unwrap();
        assert!(val["runs"].as_array().is_some());
        assert_eq!(val["runs"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn sarif_tool_name_is_correct() {
        let report = sample_report();
        let sarif = render(&report).unwrap();
        let val: serde_json::Value = serde_json::from_str(&sarif).unwrap();
        let tool_name = &val["runs"][0]["tool"]["driver"]["name"];
        assert_eq!(tool_name.as_str().unwrap(), "sf-keyaudit");
    }

    #[test]
    fn sarif_result_level_is_error() {
        let report = sample_report();
        let sarif = render(&report).unwrap();
        let val: serde_json::Value = serde_json::from_str(&sarif).unwrap();
        let results = val["runs"][0]["results"].as_array().unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0]["level"].as_str().unwrap(), "error");
    }

    #[test]
    fn sarif_rule_id_matches_pattern_id() {
        let report = sample_report();
        let sarif = render(&report).unwrap();
        let val: serde_json::Value = serde_json::from_str(&sarif).unwrap();
        let results = val["runs"][0]["results"].as_array().unwrap();
        assert_eq!(
            results[0]["ruleId"].as_str().unwrap(),
            "openai-project-key-v2"
        );
    }

    #[test]
    fn sarif_location_has_correct_line_number() {
        let report = sample_report();
        let sarif = render(&report).unwrap();
        let val: serde_json::Value = serde_json::from_str(&sarif).unwrap();
        let loc = &val["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"];
        assert_eq!(loc["startLine"].as_u64().unwrap(), 42);
    }

    #[test]
    fn sarif_empty_findings_produces_empty_results() {
        let mut report = sample_report();
        report.findings = vec![];
        report.summary = Summary::default();
        let sarif = render(&report).unwrap();
        let val: serde_json::Value = serde_json::from_str(&sarif).unwrap();
        let results = val["runs"][0]["results"].as_array().unwrap();
        assert_eq!(results.len(), 0);
    }

    #[test]
    fn sarif_rules_deduplicated() {
        let mut report = sample_report();
        // Two findings with the same pattern_id
        let f2 = Finding::new(
            2, "openai", "src/other.py", 5, 1,
            "sk-proj-***REDACTED***".into(), "openai-project-key-v2", 4.5
        );
        report.findings.push(f2);
        let sarif = render(&report).unwrap();
        let val: serde_json::Value = serde_json::from_str(&sarif).unwrap();
        let rules = val["runs"][0]["tool"]["driver"]["rules"].as_array().unwrap();
        // Should only have one rule for openai-project-key-v2
        assert_eq!(rules.len(), 1);
    }
}
