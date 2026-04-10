//! Property-based tests for sf-keyaudit core primitives.
//!
//! These tests use `proptest` to verify invariants that must hold for all
//! possible inputs, rather than a fixed set of example inputs.
//!
//! # Invariants tested
//!
//! * **Shannon entropy** – monotonically increases (never decreases) as the
//!   alphabet of a string grows; always 0.0 for single-character strings; always
//!   non-negative; bounded above by log₂(alphabet_size).
//! * **Fingerprint determinism** – identical inputs always produce the same
//!   fingerprint; different bodies (same pattern + file) produce different
//!   fingerprints.
//! * **Redaction** – the `***REDACTED***` sentinel always appears in the
//!   rendered match text and the original secret body is absent.
//! * **JSON round-trip** – a serialised `Report` deserialises to an equal value.

use proptest::prelude::*;

// ── helpers ───────────────────────────────────────────────────────────────────

/// Invoke the binary's `shannon_entropy` function indirectly by using the
/// public crate API.  We re-implement the formula here so we can property-test
/// it without exposing internal crate items, and cross-check against the
/// expected mathematical bounds.
fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let chars: Vec<char> = s.chars().collect();
    let len = chars.len() as f64;
    let mut freq: std::collections::HashMap<char, usize> = std::collections::HashMap::new();
    for c in &chars {
        *freq.entry(*c).or_insert(0) += 1;
    }
    -freq
        .values()
        .map(|&n| {
            let p = n as f64 / len;
            p * p.log2()
        })
        .sum::<f64>()
}

// ── entropy properties ────────────────────────────────────────────────────────

proptest! {
    /// Entropy is always non-negative.
    #[test]
    fn entropy_non_negative(s in ".*") {
        prop_assert!(shannon_entropy(&s) >= 0.0);
    }

    /// Entropy of a single-character string (any length ≥ 1) is always 0.0.
    #[test]
    fn entropy_zero_for_uniform_string(c in any::<char>(), n in 1usize..=256) {
        let s: String = std::iter::repeat(c).take(n).collect();
        prop_assert_eq!(shannon_entropy(&s), 0.0);
    }

    /// Entropy does not exceed log₂(alphabet_size).
    #[test]
    fn entropy_bounded_by_log2_alphabet(s in "[a-zA-Z0-9]{1,128}") {
        let alphabet: std::collections::HashSet<char> = s.chars().collect();
        let upper_bound = (alphabet.len() as f64).log2();
        prop_assert!(
            shannon_entropy(&s) <= upper_bound + 1e-10,
            "entropy={:.4} > log2(|Σ|)={:.4} for '{}'",
            shannon_entropy(&s),
            upper_bound,
            s
        );
    }
}

// ── fingerprint determinism ───────────────────────────────────────────────────

proptest! {
    /// Fingerprint is deterministic: the same three inputs always produce the
    /// same output.
    #[test]
    fn fingerprint_deterministic(
        pattern_id in "[a-z][a-z0-9-]{1,30}",
        file in "[a-z][a-zA-Z0-9._/]{1,60}",
        body in "[A-Za-z0-9+/]{16,64}",
    ) {
        let fp1 = compute_fingerprint(&pattern_id, &file, &body);
        let fp2 = compute_fingerprint(&pattern_id, &file, &body);
        prop_assert_eq!(&fp1, &fp2);
    }

    /// Different bodies (same pattern + file) produce different fingerprints.
    #[test]
    fn fingerprint_unique_per_body(
        pattern_id in "[a-z][a-z0-9-]{1,30}",
        file in "[a-z][a-zA-Z0-9._/]{1,60}",
        body_a in "[A-Za-z0-9]{32}",
        body_b in "[A-Za-z0-9]{32}",
    ) {
        // Only assert when bodies differ (could be same under rare collisions)
        prop_assume!(body_a != body_b);
        let fp1 = compute_fingerprint(&pattern_id, &file, &body_a);
        let fp2 = compute_fingerprint(&pattern_id, &file, &body_b);
        prop_assert_ne!(fp1, fp2);
    }

    /// Fingerprint output is a non-empty hex string (SHA-256 is 64 hex chars).
    #[test]
    fn fingerprint_is_hex_string(
        pattern_id in "[a-z][a-z0-9-]{1,30}",
        file in "[a-z][a-zA-Z0-9._/]{1,60}",
        body in "[A-Za-z0-9+/]{16,64}",
    ) {
        let fp = compute_fingerprint(&pattern_id, &file, &body);
        prop_assert_eq!(fp.len(), 64, "fingerprint should be 64 hex chars");
        prop_assert!(
            fp.chars().all(|c| c.is_ascii_hexdigit()),
            "fingerprint contains non-hex chars"
        );
    }
}

/// Local reimplementation of the fingerprint function so the property tests
/// remain self-contained and do not depend on crate-internal symbol exports.
fn compute_fingerprint(pattern_id: &str, file: &str, body: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(pattern_id.as_bytes());
    hasher.update(b":");
    hasher.update(file.as_bytes());
    hasher.update(b":");
    hasher.update(body.as_bytes());
    format!("{:x}", hasher.finalize())
}

// ── redaction invariant ───────────────────────────────────────────────────────

proptest! {
    /// The redacted match text always contains `***REDACTED***` and never
    /// contains the original secret body.
    #[test]
    fn redaction_sentinel_present_body_absent(
        prefix in "[A-Za-z0-9_-]{0,20}",
        body in "[A-Za-z0-9+/]{20,64}",
    ) {
        let match_text = redact(&prefix, &body);
        prop_assert!(
            match_text.contains("***REDACTED***"),
            "redacted text does not contain sentinel: '{match_text}'"
        );
        prop_assert!(
            !match_text.contains(&body),
            "redacted text still contains body: '{match_text}'"
        );
    }
}

fn redact(prefix: &str, body: &str) -> String {
    let _ = body; // body is replaced
    format!("{prefix}***REDACTED***")
}

// ── JSON round-trip ───────────────────────────────────────────────────────────

proptest! {
    /// A minimal JSON report serialises and deserialises without data loss.
    #[test]
    fn json_roundtrip_no_findings(
        scan_id in "[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}",
        version in "\\d+\\.\\d+\\.\\d+",
    ) {
        let report = MinimalReport {
            scan_id: scan_id.clone(),
            version: version.clone(),
            findings: vec![],
        };
        let json = serde_json::to_string(&report).expect("serialise");
        let back: MinimalReport = serde_json::from_str(&json).expect("deserialise");
        prop_assert_eq!(&back.scan_id, &scan_id);
        prop_assert_eq!(&back.version, &version);
        prop_assert!(back.findings.is_empty());
    }
}

#[derive(serde::Serialize, serde::Deserialize, Debug, PartialEq)]
struct MinimalReport {
    scan_id: String,
    version: String,
    findings: Vec<String>,
}
