//! Human-readable text output format.
//!
//! Used when `--format text` is passed.  Output goes to stdout (or `--output`
//! file) and is designed for developer terminals rather than machine parsing.

use crate::error::AuditError;
use crate::types::{Finding, Report};

// ── Grouping enum ─────────────────────────────────────────────────────────────

/// Controls how findings are grouped in `--format text` output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupBy {
    File,
    Provider,
    Severity,
}

// ── Public entry points ───────────────────────────────────────────────────────

/// Render a [`Report`] as human-readable text (no grouping).
pub fn render(report: &Report) -> Result<String, AuditError> {
    render_with_options(report, None, false)
}

/// Render a [`Report`] as human-readable text with optional grouping.
/// Color is off; call [`render_with_options`] directly for color support.
pub fn render_with_grouping(
    report: &Report,
    group_by: Option<GroupBy>,
) -> Result<String, AuditError> {
    render_with_options(report, group_by, false)
}

/// Render with optional grouping *and* optional ANSI color.
///
/// Set `color = true` only when outputting to a real terminal; colors use
/// standard ANSI escape sequences and are reset after each styled span.
pub fn render_with_options(
    report: &Report,
    group_by: Option<GroupBy>,
    color: bool,
) -> Result<String, AuditError> {
    let sep = "─".repeat(72);
    let mut lines: Vec<String> = Vec::new();

    // ── header ────────────────────────────────────────────────────────────────
    lines.push(format!(
        "sf-keyaudit v{}  |  {}",
        report.version, report.timestamp
    ));
    lines.push(format!("Scan root:   {}", report.scan_root));
    lines.push(format!(
        "Files:       {} scanned, {} skipped  |  Duration: {}ms",
        report.files_scanned,
        report.metrics.files_skipped,
        report.metrics.scan_duration_ms
    ));
    if report.metrics.notebooks_scanned > 0 {
        lines.push(format!(
            "Notebooks:   {} scanned",
            report.metrics.notebooks_scanned
        ));
    }
    if report.metrics.archives_scanned > 0 {
        lines.push(format!(
            "Archives:    {} scanned",
            report.metrics.archives_scanned
        ));
    }
    if report.metrics.cached_files_skipped > 0 {
        lines.push(format!(
            "Cache hits:  {} files skipped (unchanged content)",
            report.metrics.cached_files_skipped
        ));
    }
    lines.push(sep.clone());

    // ── findings ──────────────────────────────────────────────────────────────
    if report.findings.is_empty() {
        lines.push("No high-confidence findings detected.".to_string());
    } else {
        lines.push(format!("FINDINGS: {}", report.findings.len()));
        lines.push(String::new());

        // Sort for deterministic output.
        let mut sorted = report.findings.clone();
        sorted.sort_by(|a, b| {
            a.file
                .cmp(&b.file)
                .then(a.line.cmp(&b.line))
                .then(a.pattern_id.cmp(&b.pattern_id))
        });

        match group_by {
            Some(GroupBy::File) => render_grouped_by_field(
                &sorted,
                |f| f.file.clone(),
                "FILE",
                &mut lines,
                color,
            ),
            Some(GroupBy::Provider) => render_grouped_by_field(
                &sorted,
                |f| f.provider.clone(),
                "PROVIDER",
                &mut lines,
                color,
            ),
            Some(GroupBy::Severity) => {
                // Custom ordered iteration: critical → high → medium → other.
                let order = ["critical", "high", "medium"];
                let mut done: std::collections::HashSet<String> = std::collections::HashSet::new();
                for sev in &order {
                    let group: Vec<_> = sorted
                        .iter()
                        .filter(|f| f.severity.to_lowercase() == *sev)
                        .collect();
                    if group.is_empty() {
                        continue;
                    }
                    lines.push(if color {
                        format!(
                            "{}── SEVERITY: {} ({}) ──{}",
                            severity_color(sev),
                            sev.to_uppercase(),
                            group.len(),
                            COLOR_RESET
                        )
                    } else {
                        format!("── SEVERITY: {} ({}) ──", sev.to_uppercase(), group.len())
                    });
                    for f in &group {
                        render_finding(f, &mut lines, color);
                        done.insert(f.fingerprint.clone());
                    }
                }
                // Anything not in the ordered list.
                for f in sorted.iter().filter(|f| !done.contains(&f.fingerprint)) {
                    render_finding(f, &mut lines, color);
                }
            }
            None => {
                for f in &sorted {
                    render_finding(f, &mut lines, color);
                }
            }
        }
    }

    // ── low-confidence note ───────────────────────────────────────────────────
    if !report.low_confidence_findings.is_empty() {
        lines.push(format!(
            "LOW-CONFIDENCE findings (informational, exit 0): {}",
            report.low_confidence_findings.len()
        ));
    }

    // ── baselined note ────────────────────────────────────────────────────────
    if !report.baselined_findings.is_empty() {
        lines.push(format!(
            "BASELINED findings (excluded by --baseline): {}",
            report.baselined_findings.len()
        ));
    }

    // ── suppressed note ───────────────────────────────────────────────────────
    if report.metrics.suppressed_count > 0 {
        lines.push(format!(
            "SUPPRESSED by allowlist: {}",
            report.metrics.suppressed_count
        ));
    }

    lines.push(sep);

    // ── summary ───────────────────────────────────────────────────────────────
    lines.push(format!(
        "SUMMARY:  {} finding(s) across {} file(s)",
        report.summary.total_findings, report.summary.files_with_findings
    ));

    if !report.summary.by_provider.is_empty() {
        let mut providers: Vec<(&String, &usize)> = report.summary.by_provider.iter().collect();
        providers.sort_by_key(|(k, _)| k.as_str());
        let breakdown: Vec<String> = providers.iter().map(|(k, v)| format!("{k}: {v}")).collect();
        lines.push(format!("          By provider:  {}", breakdown.join("  ")));
    }

    Ok(lines.join("\n") + "\n")
}

// ── Color support ────────────────────────────────────────────────────────────

const COLOR_RESET: &str = "\x1b[0m";
const COLOR_CRITICAL: &str = "\x1b[1;31m"; // bold red
const COLOR_HIGH: &str = "\x1b[1;33m";     // bold yellow
const COLOR_MEDIUM: &str = "\x1b[1;36m";   // bold cyan
const COLOR_LOW: &str = "\x1b[0;37m";      // dim

fn severity_color(severity: &str) -> &'static str {
    match severity.to_lowercase().as_str() {
        "critical" => COLOR_CRITICAL,
        "high" => COLOR_HIGH,
        "medium" => COLOR_MEDIUM,
        _ => COLOR_LOW,
    }
}

// ── Rendering helpers ─────────────────────────────────────────────────────────

fn render_grouped_by_field(
    findings: &[Finding],
    key_fn: impl Fn(&Finding) -> String,
    label: &str,
    lines: &mut Vec<String>,
    color: bool,
) {
    let mut groups: indexmap::IndexMap<String, Vec<&Finding>> = indexmap::IndexMap::new();
    for f in findings {
        groups.entry(key_fn(f)).or_default().push(f);
    }
    for (key, group) in &groups {
        lines.push(format!("── {label}: {} ({}) ──", key, group.len()));
        for f in group {
            render_finding(f, lines, color);
        }
    }
}

fn render_finding(f: &Finding, lines: &mut Vec<String>, color: bool) {
    let severity_str = f.severity.to_uppercase();
    let prefix_line = if color {
        format!(
            "{}[{}]{} {}  /  {}",
            severity_color(&f.severity),
            severity_str,
            COLOR_RESET,
            f.provider,
            f.pattern_id
        )
    } else {
        format!("[{}] {}  /  {}", severity_str, f.provider, f.pattern_id)
    };
    lines.push(prefix_line);
    lines.push(format!("  File:        {}:{}", f.file, f.line));
    lines.push(format!("  Match:       {}", f.match_text));
    lines.push(format!("  Entropy:     {:.2} bits/char", f.entropy));
    lines.push(format!("  Fingerprint: {}", f.fingerprint));
    if let Some(ref status) = f.validation_status {
        lines.push(format!("  Validation:  {status}"));
    }
    if let Some(ref owner) = f.owner {
        lines.push(format!("  Owner:       {owner}"));
    }
    if let Some(ref author) = f.last_author {
        lines.push(format!("  Last author: {author}"));
    }
    if let Some(ref rem) = f.remediation {
        lines.push(format!("  Remediate:   {}", wrap(rem, 68, 15)));
    }
    lines.push(String::new());
}

/// Very simple word-wrap helper: inserts a newline + `indent` spaces when a
/// segment would exceed `width` chars.  Used for remediation text.
fn wrap(s: &str, width: usize, indent: usize) -> String {
    if s.len() <= width {
        return s.to_string();
    }
    let pad = " ".repeat(indent);
    let mut result = String::new();
    let mut current_len = 0usize;
    for word in s.split_whitespace() {
        if current_len + word.len() + 1 > width && current_len > 0 {
            result.push('\n');
            result.push_str(&pad);
            current_len = 0;
        } else if current_len > 0 {
            result.push(' ');
            current_len += 1;
        }
        result.push_str(word);
        current_len += word.len();
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Finding, Report, ScanMetrics, Summary};

    fn clean_report() -> Report {
        Report {
            scan_id: "test-id".into(),
            tool: "sf-keyaudit".into(),
            version: "2.0.0".into(),
            timestamp: "2026-04-04T10:00:00Z".into(),
            scan_root: "/home/user/project".into(),
            files_scanned: 10,
            findings: vec![],
            low_confidence_findings: vec![],
            baselined_findings: vec![],
            summary: Summary::default(),
            metrics: ScanMetrics {
                scan_duration_ms: 42,
                files_skipped: 1,
                ..ScanMetrics::default()
            },
        }
    }

    fn report_with_finding() -> Report {
        let f = Finding::new(
            1,
            "openai",
            "src/config.py",
            12,
            1,
            "sk-proj-***REDACTED***".into(),
            "openai-project-key-v2",
            4.87,
        );
        let summary = Summary::from_findings(&[f.clone()]);
        Report {
            findings: vec![f],
            ..clean_report()
        }
        .with_summary(summary)
    }

    impl Report {
        fn with_summary(mut self, s: Summary) -> Self {
            self.summary = s;
            self
        }
    }

    #[test]
    fn clean_report_contains_no_findings_message() {
        let text = render(&clean_report()).unwrap();
        assert!(text.contains("No high-confidence findings detected."));
    }

    #[test]
    fn report_with_finding_contains_finding_info() {
        let text = render(&report_with_finding()).unwrap();
        assert!(text.contains("src/config.py:12"));
        assert!(text.contains("openai"));
        assert!(text.contains("***REDACTED***"));
        assert!(text.contains("fp-"));
    }

    #[test]
    fn text_contains_scan_stats() {
        let text = render(&clean_report()).unwrap();
        assert!(text.contains("Files:"));
        assert!(text.contains("42ms"));
        assert!(text.contains("10 scanned"));
    }

    #[test]
    fn text_contains_summary_section() {
        let text = render(&report_with_finding()).unwrap();
        assert!(text.contains("SUMMARY:"));
        assert!(text.contains("1 finding(s)"));
    }

    #[test]
    fn text_shows_severity_uppercase() {
        let text = render(&report_with_finding()).unwrap();
        // Default severity from Finding::new is "critical", shown uppercase
        assert!(text.contains("[CRITICAL]") || text.contains("[HIGH]") || text.contains("[MEDIUM]"));
    }

    #[test]
    fn text_shows_fingerprint() {
        let text = render(&report_with_finding()).unwrap();
        assert!(text.contains("Fingerprint: fp-"));
    }

    #[test]
    fn wrap_short_string_unchanged() {
        assert_eq!(wrap("hello", 20, 4), "hello");
    }

    #[test]
    fn wrap_long_string_gets_newline() {
        let s = "word1 word2 word3 word4 word5 word6 word7 word8 word9 word10";
        let result = wrap(s, 20, 4);
        assert!(result.contains('\n'));
    }
}
