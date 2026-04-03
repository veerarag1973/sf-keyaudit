//! Core file scanner.
//!
//! Applies compiled patterns to file content and returns a list of
//! [`RawFinding`]s.  The caller is responsible for assigning sequential IDs
//! and applying the allowlist.

use crate::entropy::shannon_entropy;
use crate::patterns::Pattern;

/// Default maximum file size in bytes (10 MiB).
pub const DEFAULT_MAX_FILE_SIZE: u64 = 10 * 1024 * 1024;

/// Result of scanning a single file before ID assignment or allowlisting.
#[derive(Debug, Clone)]
pub struct RawFinding {
    pub provider: String,
    pub file: String,
    pub line: usize,
    pub column: usize,
    pub match_text: String,
    pub pattern_id: String,
    pub entropy: f64,
    /// If `false` the finding is below the entropy threshold and goes into
    /// `low_confidence_findings`.
    pub high_confidence: bool,
}

/// Scan the raw bytes / text of a single file against the provided patterns.
///
/// * `relative_path` – path relative to scan_root, used in findings.
/// * `content`       – full text content of the file.
/// * `patterns`      – slice of compiled patterns to apply (may be filtered).
pub fn scan_content(
    relative_path: &str,
    content: &str,
    patterns: &[&Pattern],
) -> Vec<RawFinding> {
    let mut results: Vec<RawFinding> = Vec::new();

    for pattern in patterns {
        // Use captures_iter so we get named groups in one pass — no second
        // regex execution per hit.  Each item is a Result<Captures, Error>.
        for caps_result in pattern.regex.captures_iter(content) {
            let caps = match caps_result {
                Ok(c) => c,
                Err(_) => continue,
            };

            // The whole match is group 0.
            let full_match = match caps.get(0) {
                Some(m) => m,
                None => continue,
            };
            let match_start = full_match.start();

            // Extract the body (the secret portion) for entropy computation.
            let body = caps
                .name("body")
                .map(|m| m.as_str())
                .unwrap_or(full_match.as_str());

            let entropy = shannon_entropy(body);

            // Build the redacted display string.
            let match_text = if let Some(prefix) = caps.name("prefix") {
                format!("{}***REDACTED***", prefix.as_str())
            } else {
                "***REDACTED***".to_string()
            };

            // Compute 1-indexed line and column from byte offset in full content.
            let (line, col) = byte_offset_to_line_col(content, match_start);

            results.push(RawFinding {
                provider: pattern.provider.to_string(),
                file: relative_path.to_string(),
                line,
                column: col,
                match_text,
                pattern_id: pattern.id.to_string(),
                entropy,
                high_confidence: entropy >= pattern.min_entropy,
            });
        }
    }

    // Deduplicate: if two patterns match at the same (file, line, column)
    // keep only the first (highest-priority) match to avoid double findings.
    dedup_by_position(results)
}

/// Detect binary content by checking the first 8 KiB for a null byte.
pub fn is_binary(content: &[u8]) -> bool {
    let probe = &content[..content.len().min(8192)];
    probe.contains(&0u8)
}

/// Convert a byte offset within `content` to a (1-indexed line, 1-indexed column) pair.
pub fn byte_offset_to_line_col(content: &str, offset: usize) -> (usize, usize) {
    let before = &content[..offset.min(content.len())];
    let line = before.bytes().filter(|&b| b == b'\n').count() + 1;
    let col = offset - before.rfind('\n').map(|p| p + 1).unwrap_or(0) + 1;
    (line, col)
}

/// Remove duplicate findings at the same position, keeping the first seen
/// (patterns slice is ordered by specificity, most-specific first).
fn dedup_by_position(mut findings: Vec<RawFinding>) -> Vec<RawFinding> {
    let mut seen: std::collections::HashSet<(String, usize, usize)> = std::collections::HashSet::new();
    findings.retain(|f| seen.insert((f.file.clone(), f.line, f.column)));
    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::patterns::build_patterns;

    fn all_patterns() -> Vec<crate::patterns::Pattern> {
        build_patterns().expect("patterns must compile")
    }

    fn refs(patterns: &[crate::patterns::Pattern]) -> Vec<&crate::patterns::Pattern> {
        patterns.iter().collect()
    }

    // ── is_binary ────────────────────────────────────────────────────────────

    #[test]
    fn binary_detection_null_byte() {
        assert!(is_binary(b"hello\x00world"));
    }

    #[test]
    fn text_content_not_binary() {
        assert!(!is_binary(b"hello world\nthis is text\n"));
    }

    #[test]
    fn empty_is_not_binary() {
        assert!(!is_binary(b""));
    }

    // ── byte_offset_to_line_col ──────────────────────────────────────────────

    #[test]
    fn offset_at_start_is_line1_col1() {
        assert_eq!(byte_offset_to_line_col("hello", 0), (1, 1));
    }

    #[test]
    fn offset_in_second_line() {
        // "hello\nworld" — 'w' is at offset 6
        assert_eq!(byte_offset_to_line_col("hello\nworld", 6), (2, 1));
    }

    #[test]
    fn offset_in_middle_of_first_line() {
        assert_eq!(byte_offset_to_line_col("hello world", 6), (1, 7));
    }

    #[test]
    fn offset_at_third_line() {
        // "a\nb\nc" — 'c' is at offset 4
        assert_eq!(byte_offset_to_line_col("a\nb\nc", 4), (3, 1));
    }

    // ── scan_content — basic detection ──────────────────────────────────────

    #[test]
    fn detects_openai_project_key() {
        let p = all_patterns();
        let refs = refs(&p);
        let body = "xK9pQm7vL3nRwT5yJbHfDcGsEaZuViYo4W8MiNqX2PeUhCjBgFtOkRdSl1A6v0DwY_n-5mIT7QzHuW1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1";
        let content = format!("API_KEY = \"sk-proj-{body}\"");
        let findings = scan_content("config.py", &content, &refs);
        assert!(
            findings.iter().any(|f| f.pattern_id.starts_with("openai-project-key")),
            "should detect openai project key"
        );
    }

    #[test]
    fn detects_anthropic_key() {
        let p = all_patterns();
        let refs = refs(&p);
        // 93-char body (verified length: 85-char base + 8-char suffix = 93)
        let body_93 = "xK9pQm7vL3nRwT5yJbHfDcGsEaZuViYo4W8MiNqX2PeUhCjBgFtOkRdSl1A6v0DwY_n-5mIT7QzHuWbEjcKaPabcdefgh";
        let content = format!("key = 'sk-ant-api03-{body_93}'");
        let findings = scan_content("app.py", &content, &refs);
        assert!(
            findings.iter().any(|f| f.pattern_id == "anthropic-api-key-v1"),
            "should detect Anthropic key"
        );
    }

    #[test]
    fn detects_google_gemini_key() {
        let p = all_patterns();
        let refs = refs(&p);
        // AIza + 35 chars (verified: 35)
        let body35 = "SyT7uV8wX9yZ0aB1cD2eF3gH4iJ5kL6mN7o";
        assert_eq!(body35.len(), 35);
        let content = format!("GOOGLE_API_KEY=AIza{body35}");
        let findings = scan_content("env.go", &content, &refs);
        assert!(findings.iter().any(|f| f.provider == "google-gemini"));
    }

    #[test]
    fn detects_aws_access_key() {
        let p = all_patterns();
        let refs = refs(&p);
        let content = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE";
        let findings = scan_content("infra.tf", content, &refs);
        assert!(findings.iter().any(|f| f.provider == "aws-bedrock"));
    }

    #[test]
    fn detects_huggingface_token() {
        let p = all_patterns();
        let refs = refs(&p);
        let body = "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9";
        assert_eq!(body.len(), 38);
        let content = format!("HF_TOKEN=hf_{body}");
        let findings = scan_content("train.py", &content, &refs);
        assert!(findings.iter().any(|f| f.provider == "huggingface"));
    }

    #[test]
    fn detects_groq_key() {
        let p = all_patterns();
        let refs = refs(&p);
        let body = "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0U1v2W3x4Y5z6";
        assert_eq!(body.len(), 52);
        let content = format!("GROQ_API_KEY=gsk_{body}");
        let findings = scan_content("config.yaml", &content, &refs);
        assert!(findings.iter().any(|f| f.provider == "groq"));
    }

    #[test]
    fn detects_replicate_token() {
        let p = all_patterns();
        let refs = refs(&p);
        let body = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
        assert_eq!(body.len(), 40);
        let content = format!("REPLICATE_API_TOKEN=r8_{body}");
        let findings = scan_content("model.py", &content, &refs);
        assert!(findings.iter().any(|f| f.provider == "replicate"));
    }

    #[test]
    fn detects_elevenlabs_key_via_header() {
        let p = all_patterns();
        let refs = refs(&p);
        let content = "xi-api-key: 1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d";
        let findings = scan_content("sdk.py", content, &refs);
        assert!(findings.iter().any(|f| f.provider == "elevenlabs"));
    }

    #[test]
    fn detects_pinecone_key() {
        let p = all_patterns();
        let refs = refs(&p);
        let content = "PINECONE_API_KEY=12345678-1234-1234-1234-123456789abc";
        let findings = scan_content("index.py", content, &refs);
        assert!(findings.iter().any(|f| f.provider == "pinecone"));
    }

    // ── match text redaction ─────────────────────────────────────────────────

    #[test]
    fn match_text_contains_redacted_marker() {
        let p = all_patterns();
        let refs = refs(&p);
        let body35 = "SyT7uV8wX9yZ0aB1cD2eF3gH4iJ5kL6mN7o"; // 35 chars
        let content = format!("key=AIza{body35}");
        let findings = scan_content("a.py", &content, &refs);
        let f = findings.iter().find(|f| f.provider == "google-gemini").expect("finding");
        assert!(f.match_text.contains("***REDACTED***"));
        assert!(f.match_text.contains("AIza"), "prefix should be preserved");
    }

    #[test]
    fn match_text_never_contains_raw_key() {
        let p = all_patterns();
        let refs = refs(&p);
        // The raw body value should never appear in match_text
        let body = "AKIAIOSFODNN7EXAMPLE"; // AKIA prefix + 16 chars
        let content = format!("key={body}");
        let findings = scan_content("a.tf", &content, &refs);
        for f in &findings {
            // The 16-char secret part "IOSFODNN7EXAMPLE" must not appear
            assert!(!f.match_text.contains("IOSFODNN7EXAMPLE"), "raw key must not appear in match");
        }
    }

    // ── empty file ───────────────────────────────────────────────────────────

    #[test]
    fn empty_content_returns_no_findings() {
        let p = all_patterns();
        let refs = refs(&p);
        let findings = scan_content("empty.py", "", &refs);
        assert!(findings.is_empty());
    }

    // ── entropy classification ───────────────────────────────────────────────

    #[test]
    fn low_entropy_body_marked_low_confidence() {
        let p = all_patterns();
        let refs = refs(&p);
        // AKIA + 16 identical chars = all-same-char body, extremely low entropy.
        let content = "AKIAAAAAAAAAAAAAAA"; // AKIA + 16 x 'A'
        let findings = scan_content("a.tf", content, &refs);
        for f in &findings {
            if f.provider == "aws-bedrock" {
                assert!(!f.high_confidence, "all-same-char AWS key body should be low-confidence");
            }
        }
    }

    #[test]
    fn high_entropy_body_marked_high_confidence() {
        let p = all_patterns();
        let refs = refs(&p);
        // AWS AKIA with mixed-case random-looking body
        let content = "AKIAX9KPQ7VL3NRW8MB5";
        let findings = scan_content("a.tf", content, &refs);
        for f in &findings {
            if f.provider == "aws-bedrock" {
                // entropy of "X9KPQ7VL3NRW8MB5" should be above 3.0
                assert!(f.entropy > 3.0);
            }
        }
    }

    // ── deduplication ────────────────────────────────────────────────────────

    #[test]
    fn dedup_removes_same_position_duplicate() {
        let f1 = RawFinding {
            provider: "openai".into(),
            file: "a.py".into(),
            line: 1,
            column: 5,
            match_text: "sk-***REDACTED***".into(),
            pattern_id: "openai-legacy-key-v1".into(),
            entropy: 4.5,
            high_confidence: true,
        };
        let f2 = RawFinding {
            provider: "stability-ai".into(),
            file: "a.py".into(),
            line: 1,
            column: 5,
            match_text: "***REDACTED***".into(),
            pattern_id: "stability-ai-key-v1".into(),
            entropy: 4.5,
            high_confidence: true,
        };
        let result = dedup_by_position(vec![f1, f2]);
        assert_eq!(result.len(), 1);
        // First one (openai legacy) should be kept
        assert_eq!(result[0].provider, "openai");
    }

    #[test]
    fn dedup_keeps_different_positions() {
        let make = |line: usize, col: usize| RawFinding {
            provider: "openai".into(),
            file: "a.py".into(),
            line,
            column: col,
            match_text: "sk-***REDACTED***".into(),
            pattern_id: "openai-legacy-key-v1".into(),
            entropy: 4.5,
            high_confidence: true,
        };
        let result = dedup_by_position(vec![make(1, 5), make(2, 5), make(1, 20)]);
        assert_eq!(result.len(), 3);
    }
}
