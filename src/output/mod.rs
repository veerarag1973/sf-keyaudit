pub mod json;
pub mod sarif;
pub mod text;

use crate::error::AuditError;
use crate::types::{OutputFormat, Report};
use std::path::Path;

/// Write the report to `path` (if `Some`) or return it as a `String`.
pub fn render(
    report: &Report,
    format: OutputFormat,
    output_path: Option<&Path>,
) -> Result<Option<String>, AuditError> {
    let rendered = match format {
        OutputFormat::Json => json::render(report)?,
        OutputFormat::Sarif => sarif::render(report)?,
        OutputFormat::Text => text::render(report)?,
    };

    match output_path {
        Some(path) => {
            std::fs::write(path, &rendered).map_err(|source| AuditError::OutputWrite {
                path: path.display().to_string(),
                source,
            })?;
            Ok(None)
        }
        None => Ok(Some(rendered)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Finding, Report, Summary};
    use std::collections::HashMap;
    use tempfile::TempDir;

    fn empty_report() -> Report {
        Report {
            scan_id: "test-id".to_string(),
            tool: "sf-keyaudit".to_string(),
            version: "2.0.0".to_string(),
            timestamp: "2024-01-01T00:00:00Z".to_string(),
            scan_root: "/tmp".to_string(),
            files_scanned: 0,
            findings: vec![],
            low_confidence_findings: vec![],
            baselined_findings: vec![],
            summary: Summary {
                total_findings: 0,
                by_provider: HashMap::new(),
                files_with_findings: 0,
            },
            metrics: crate::types::ScanMetrics::default(),
        }
    }

    fn finding() -> Finding {
        Finding::new(1, "openai", "src/main.py", 1, 1, "sk-***REDACTED***".to_string(), "openai-legacy-key-v1", 4.5)
    }

    fn report_with_finding() -> Report {
        let f = finding();
        Report {
            scan_id: "test-id".to_string(),
            tool: "sf-keyaudit".to_string(),
            version: "2.0.0".to_string(),
            timestamp: "2024-01-01T00:00:00Z".to_string(),
            scan_root: "/tmp".to_string(),
            files_scanned: 1,
            summary: Summary::from_findings(&[f.clone()]),
            findings: vec![f],
            low_confidence_findings: vec![],
            baselined_findings: vec![],
            metrics: crate::types::ScanMetrics::default(),
        }
    }

    #[test]
    fn render_json_returns_some_string() {
        let report = empty_report();
        let result = render(&report, OutputFormat::Json, None).unwrap();
        assert!(result.is_some());
        let s = result.unwrap();
        assert!(s.contains("sf-keyaudit"));
    }

    #[test]
    fn render_sarif_returns_some_string() {
        let report = empty_report();
        let result = render(&report, OutputFormat::Sarif, None).unwrap();
        assert!(result.is_some());
        let s = result.unwrap();
        assert!(s.contains("2.1.0"));
    }

    #[test]
    fn render_text_returns_some_string() {
        let report = report_with_finding();
        let result = render(&report, OutputFormat::Text, None).unwrap();
        assert!(result.is_some());
        let s = result.unwrap();
        assert!(s.contains("sf-keyaudit"), "text output should contain tool name");
        assert!(s.contains("openai"), "text output should contain provider");
    }

    #[test]
    fn render_writes_to_file_returns_none() {
        let dir: TempDir = tempfile::tempdir().unwrap();
        let path = dir.path().join("report.json");
        let report = empty_report();
        let result = render(&report, OutputFormat::Json, Some(&path)).unwrap();
        assert!(result.is_none());
        assert!(path.exists());
    }

    #[test]
    fn render_with_finding_includes_finding_in_json() {
        let report = report_with_finding();
        let result = render(&report, OutputFormat::Json, None).unwrap();
        let s = result.unwrap();
        assert!(s.contains("openai"));
    }

    #[test]
    fn render_sarif_with_finding_has_results() {
        let report = report_with_finding();
        let result = render(&report, OutputFormat::Sarif, None).unwrap();
        let s = result.unwrap();
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        let results = &v["runs"][0]["results"];
        assert!(results.as_array().map(|a| !a.is_empty()).unwrap_or(false));
    }

    #[test]
    fn render_write_to_nonexistent_parent_returns_error() {
        let report = empty_report();
        // Path with a non-existent parent directory → fs::write fails → AuditError::OutputWrite
        let bad_path = std::path::Path::new("/nonexistent_sf_audit_dir_xyz/report.json");
        let result = render(&report, OutputFormat::Json, Some(bad_path));
        assert!(result.is_err(), "writing to nonexistent directory must fail");
    }
}

