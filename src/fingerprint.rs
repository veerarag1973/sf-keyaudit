//! Stable finding fingerprints.
//!
//! Each fingerprint is derived from the pattern identifier, the relative file
//! path, and the **matched credential body** (the raw secret value, not the
//! redacted display string).  Excluding line numbers means the fingerprint
//! survives line-number shifts caused by inserting or removing unrelated code
//! above the secret.
//!
//! Output format: `fp-XXXXXXXXXXXXXXXX` (19 chars total — "fp-" prefix + 16 hex).

use sha2::{Digest, Sha256};

/// Compute a stable fingerprint for a finding.
///
/// `match_body` must be the **raw, unredacted** body of the matched credential
/// (i.e. the value captured by the regex named group `body`).  Inputs are
/// joined with NUL bytes to prevent trivial collisions across fields.
pub fn compute(pattern_id: &str, file: &str, match_body: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(pattern_id.as_bytes());
    hasher.update(b"\x00");
    hasher.update(file.as_bytes());
    hasher.update(b"\x00");
    hasher.update(match_body.as_bytes());
    let result = hasher.finalize();
    // First 8 bytes → 16 hex chars; provides 64-bit collision resistance,
    // suitable for monorepos with millions of findings.
    format!(
        "fp-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        result[0], result[1], result[2], result[3],
        result[4], result[5], result[6], result[7]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_has_expected_prefix_and_length() {
        let fp = compute("openai-legacy-key-v1", "src/main.py", "sk-realkey123");
        assert!(fp.starts_with("fp-"), "must start with fp-");
        assert_eq!(fp.len(), 19, "fp- + 16 hex = 19 chars");
    }

    #[test]
    fn same_inputs_produce_same_fingerprint() {
        let a = compute("openai-legacy-key-v1", "src/config.py", "sk-realkey123");
        let b = compute("openai-legacy-key-v1", "src/config.py", "sk-realkey123");
        assert_eq!(a, b);
    }

    #[test]
    fn different_file_produces_different_fingerprint() {
        let a = compute("openai-legacy-key-v1", "src/a.py", "sk-realkey123");
        let b = compute("openai-legacy-key-v1", "src/b.py", "sk-realkey123");
        assert_ne!(a, b);
    }

    #[test]
    fn different_body_produces_different_fingerprint() {
        let a = compute("openai-legacy-key-v1", "src/config.py", "sk-secret-aaa");
        let b = compute("openai-legacy-key-v1", "src/config.py", "sk-secret-bbb");
        assert_ne!(a, b);
    }

    /// The core stability guarantee: moving a secret to a different line
    /// (without changing the secret value) must NOT change its fingerprint.
    #[test]
    fn same_body_different_line_produces_same_fingerprint() {
        // Simulate the same key found at line 10 vs line 42 — fingerprint stable.
        let a = compute("openai-legacy-key-v1", "src/config.py", "sk-secret-abc123");
        let b = compute("openai-legacy-key-v1", "src/config.py", "sk-secret-abc123");
        assert_eq!(a, b, "fingerprint must not depend on line number");
    }

    #[test]
    fn different_pattern_produces_different_fingerprint() {
        let a = compute("openai-legacy-key-v1", "src/config.py", "sk-realkey123");
        let b = compute("anthropic-api-key-v1", "src/config.py", "sk-realkey123");
        assert_ne!(a, b);
    }

    #[test]
    fn fingerprint_contains_only_valid_hex_chars() {
        let fp = compute("groq-api-key-v1", "infra/vars.tf", "gsk_abc123");
        let hex_part = fp.strip_prefix("fp-").unwrap();
        assert!(hex_part.chars().all(|c| c.is_ascii_hexdigit()), "must be hex: {hex_part}");
    }
}
