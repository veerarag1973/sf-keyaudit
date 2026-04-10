/// Compute Shannon entropy (bits per character) for the given string slice.
///
/// This is used to distinguish genuine high-entropy keys from low-entropy
/// placeholder strings like "aaaaaaaaaa" or "sk-test1234test1234test1234test1234test1234test1234".
///
/// Formula: H = -Σ p(x) * log₂(p(x))
pub fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut freq = [0u32; 256];
    let len = s.len() as f64;
    for byte in s.bytes() {
        freq[byte as usize] += 1;
    }
    freq.iter()
        .filter(|&&f| f > 0)
        .map(|&f| {
            let p = f as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// Minimum entropy threshold for a finding to be considered high-confidence
/// and trigger exit code 1.  Individual patterns may set higher thresholds via
/// their own `min_entropy` field — this constant is only used when no
/// per-pattern override is available (e.g. for custom rules without an explicit
/// threshold).
pub const HIGH_CONFIDENCE_THRESHOLD: f64 = 3.5;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_string_entropy_is_zero() {
        assert_eq!(shannon_entropy(""), 0.0);
    }

    #[test]
    fn single_char_entropy_is_zero() {
        assert_eq!(shannon_entropy("a"), 0.0);
        assert_eq!(shannon_entropy("z"), 0.0);
    }

    #[test]
    fn uniform_string_entropy_is_zero() {
        // All same characters → entropy 0
        assert_eq!(shannon_entropy("aaaaaaaaaaaaaaaa"), 0.0);
    }

    #[test]
    fn two_equal_frequency_chars_entropy_is_one() {
        // "ababab..." → exactly 1.0 bit per character
        let s = "ababababababababab";
        let e = shannon_entropy(s);
        assert!((e - 1.0).abs() < 1e-10, "expected ~1.0, got {e}");
    }

    #[test]
    fn high_entropy_random_string() {
        // A synthetic key body with high character diversity
        let body = "xK9pQm7vL3nRwT5yJbHfDcGsEaZuViYo";
        let e = shannon_entropy(body);
        assert!(e > 4.0, "expected entropy > 4.0 for diverse string, got {e}");
    }

    #[test]
    fn low_entropy_placeholder_below_threshold() {
        // "sk-test" repeated — looks like a key but very low entropy
        let body = "testtesttesttesttesttesttesttesttesttest";
        assert!(shannon_entropy(body) < HIGH_CONFIDENCE_THRESHOLD);
    }

    #[test]
    fn real_looking_key_above_threshold() {
        let body = "xK9pQm7vL3nRwT5yJbHfDcGsEaZuViYo4W8MiNq";
        assert!(shannon_entropy(body) >= HIGH_CONFIDENCE_THRESHOLD);
    }

    #[test]
    fn ascii_printable_max_entropy() {
        // ~95 distinct printable ASCII chars → entropy should be ~log2(95) ≈ 6.57
        let s: String = (32u8..=126u8).map(|c| c as char).collect();
        let e = shannon_entropy(&s);
        let expected = (95f64).log2();
        assert!((e - expected).abs() < 0.01, "expected ~{expected}, got {e}");
    }
}
