//! Pattern library — one entry per provider credential format.
//!
//! Every [`Pattern`] is compiled once at startup and then reused across all
//! file scans.  Each regex must contain a named capture group called `body`
//! which is the portion of the match that contains the actual secret value.
//! An optional named group `prefix` marks the human-readable prefix that is
//! preserved verbatim in the redacted output (e.g. `sk-proj-`).
//!
//! Naming convention:  `{provider}-{keytype}-v{N}`
//! When a provider updates their key format the version number increments,
//! keeping older allowlist entries identifiable.

use crate::error::AuditError;
use fancy_regex::Regex;

/// A compiled pattern entry.
pub struct Pattern {
    /// Stable identifier, e.g. `openai-project-key-v2`.
    pub id: &'static str,
    /// Provider slug used in Finding.provider, e.g. `openai`.
    pub provider: &'static str,
    /// Human-readable one-line description.
    #[allow(dead_code)]
    pub description: &'static str,
    /// Compiled regex.  Must contain a named group `body`.
    /// May optionally contain a named group `prefix`.
    pub regex: Regex,
    /// Minimum Shannon entropy (bits/char) for the `body` capture group for
    /// the finding to be classified as high-confidence (exit 1).
    /// Matches below this threshold go into `low_confidence_findings`.
    pub min_entropy: f64,
}

impl std::fmt::Debug for Pattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pattern")
            .field("id", &self.id)
            .field("provider", &self.provider)
            .finish()
    }
}

/// Raw pattern definition used to build [`Pattern`] at startup.
struct PatternDef {
    id: &'static str,
    provider: &'static str,
    description: &'static str,
    /// Regex string.  Must include a named group `(?P<body>...)`.
    /// May include `(?P<prefix>...)` for the human-visible prefix.
    pattern: &'static str,
    min_entropy: f64,
}

/// Build and return all compiled patterns in priority order.
/// More-specific patterns appear before more-generic ones so that a finding is
/// attributed to the most precise match when deduplication runs later.
pub fn build_patterns() -> Result<Vec<Pattern>, AuditError> {
    let defs: &[PatternDef] = &[
        // ── Anthropic ──────────────────────────────────────────────────────
        PatternDef {
            id: "anthropic-api-key-v1",
            provider: "anthropic",
            description: "Anthropic Claude API key (sk-ant-api03- prefix)",
            pattern: r"(?P<prefix>sk-ant-api03-)(?P<body>[A-Za-z0-9+/=_-]{93})",
            min_entropy: 3.5,
        },
        // ── OpenAI ─────────────────────────────────────────────────────────
        PatternDef {
            id: "openai-project-key-v2",
            provider: "openai",
            description: "OpenAI project API key (sk-proj- prefix)",
            pattern: r"(?P<prefix>sk-proj-)(?P<body>[A-Za-z0-9_-]{100,200})",
            min_entropy: 4.0,
        },
        PatternDef {
            id: "openai-svcacct-key-v1",
            provider: "openai",
            description: "OpenAI service-account API key (sk-svcacct- prefix)",
            pattern: r"(?P<prefix>sk-svcacct-)(?P<body>[A-Za-z0-9_-]{100,200})",
            min_entropy: 4.0,
        },
        // ── OpenRouter ─────────────────────────────────────────────────────
        // Must appear BEFORE the generic sk- pattern to avoid false attribution.
        PatternDef {
            id: "openrouter-api-key-v1",
            provider: "openrouter",
            description: "OpenRouter API key (sk-or- prefix)",
            pattern: r"(?P<prefix>sk-or-(?:v\d+-?)?)(?P<body>[A-Za-z0-9_-]{40,100})",
            min_entropy: 3.5,
        },
        // ── OpenAI legacy / Stability AI ───────────────────────────────────
        // The sk- prefix is shared by both OpenAI legacy and Stability AI.
        // The negative lookahead avoids double-matching with the patterns above.
        PatternDef {
            id: "openai-legacy-key-v1",
            provider: "openai",
            description: "OpenAI legacy API key (bare sk- prefix, 48 alphanumeric chars)",
            pattern: r"(?P<prefix>sk-)(?!proj-|svcacct-|ant-|or-)(?P<body>[A-Za-z0-9]{48})(?:[^A-Za-z0-9]|$)",
            min_entropy: 3.5,
        },
        // ── Stability AI (context-sensitive) ───────────────────────────────
        PatternDef {
            id: "stability-ai-key-v1",
            provider: "stability-ai",
            description: "Stability AI API key (STABILITY_API_KEY context)",
            pattern: r#"(?i)(?:STABILITY(?:_AI)?_API_KEY)[\s]*[=:]["']?\s*(?P<body>sk-[A-Za-z0-9]{48})"#,
            min_entropy: 3.5,
        },
        // ── Google AI / Gemini ─────────────────────────────────────────────
        PatternDef {
            id: "google-gemini-key-v1",
            provider: "google-gemini",
            description: "Google AI / Gemini API key (AIza prefix, 39 chars total)",
            pattern: r"(?P<prefix>AIza)(?P<body>[0-9A-Za-z_-]{35})",
            min_entropy: 3.5,
        },
        // ── Google Vertex AI Service Account ───────────────────────────────
        // Detects a committed service account JSON file by looking for the
        // type marker adjacent to a private_key_id field.
        PatternDef {
            id: "google-vertex-service-account-v1",
            provider: "google-vertex-ai",
            description: "Google Vertex AI service account JSON (type:service_account with private_key_id)",
            pattern: r#"(?s)"type"\s*:\s*"service_account".{0,1000}?"private_key_id"\s*:\s*"(?P<body>[^"]{20,64})""#,
            min_entropy: 3.0,
        },
        // ── AWS Bedrock ────────────────────────────────────────────────────
        PatternDef {
            id: "aws-access-key-id-v1",
            provider: "aws-bedrock",
            description: "AWS access key ID (AKIA/ASIA prefix)",
            pattern: r"(?P<prefix>(?:AKIA|ASIA))(?P<body>[0-9A-Z]{16})",
            min_entropy: 3.0,
        },
        // ── Azure OpenAI ───────────────────────────────────────────────────
        PatternDef {
            id: "azure-openai-subscription-key-v1",
            provider: "azure-openai",
            description: "Azure OpenAI / Cognitive Services subscription key (Ocp-Apim-Subscription-Key header)",
            pattern: r#"(?i)(?P<prefix>Ocp-Apim-Subscription-Key[\s]*[:=]["']?\s*)(?P<body>[0-9a-fA-F]{32})"#,
            min_entropy: 3.0,
        },
        // ── Cohere ─────────────────────────────────────────────────────────
        PatternDef {
            id: "cohere-api-key-v1",
            provider: "cohere",
            description: "Cohere API key (co- prefix)",
            pattern: r"(?P<prefix>co-)(?P<body>[A-Za-z0-9]{40,80})",
            min_entropy: 3.5,
        },
        // ── Mistral AI ─────────────────────────────────────────────────────
        PatternDef {
            id: "mistral-api-key-v1",
            provider: "mistral-ai",
            description: "Mistral AI API key (mi- prefix with hex body)",
            pattern: r"(?P<prefix>mi-)(?P<body>[A-Za-z0-9]{40,80})",
            min_entropy: 3.5,
        },
        // ── Hugging Face ───────────────────────────────────────────────────
        PatternDef {
            id: "huggingface-token-v1",
            provider: "huggingface",
            description: "Hugging Face user access token (hf_ prefix)",
            pattern: r"(?P<prefix>hf_)(?P<body>[A-Za-z0-9]{34,50})",
            min_entropy: 3.5,
        },
        // ── Replicate ──────────────────────────────────────────────────────
        PatternDef {
            id: "replicate-api-token-v1",
            provider: "replicate",
            description: "Replicate API token (r8_ prefix, 40-char hex body)",
            pattern: r"(?P<prefix>r8_)(?P<body>[a-fA-F0-9]{40})",
            min_entropy: 3.5,
        },
        // ── Together AI ────────────────────────────────────────────────────
        PatternDef {
            id: "together-ai-key-v1",
            provider: "together-ai",
            description: "Together AI API key (context-sensitive: TOGETHER variable with 40-char hex body)",
            pattern: r#"(?i)(?:TOGETHER(?:_AI)?_API_KEY)[\s]*[=:]["']?\s*(?P<body>[a-fA-F0-9]{40,64})"#,
            min_entropy: 3.5,
        },
        // ── Groq ───────────────────────────────────────────────────────────
        PatternDef {
            id: "groq-api-key-v1",
            provider: "groq",
            description: "Groq API key (gsk_ prefix)",
            pattern: r"(?P<prefix>gsk_(?:live_|test_)?)(?P<body>[A-Za-z0-9]{52})",
            min_entropy: 3.5,
        },
        // ── Perplexity AI ──────────────────────────────────────────────────
        PatternDef {
            id: "perplexity-key-v1",
            provider: "perplexity",
            description: "Perplexity AI API key (pplx- prefix)",
            pattern: r"(?P<prefix>pplx-)(?P<body>[A-Za-z0-9]{48})",
            min_entropy: 3.5,
        },
        // ── ElevenLabs ─────────────────────────────────────────────────────
        PatternDef {
            id: "elevenlabs-api-key-v1",
            provider: "elevenlabs",
            description: "ElevenLabs API key (xi-api-key header or ELEVENLABS_API_KEY env var)",
            pattern: r#"(?i)(?P<prefix>(?:xi-api-key|ELEVENLABS_API_KEY|XI_API_KEY)[\s]*[:=]["']?\s*)(?P<body>[a-fA-F0-9]{32})"#,
            min_entropy: 3.0,
        },
        // ── Pinecone ───────────────────────────────────────────────────────
        PatternDef {
            id: "pinecone-api-key-v1",
            provider: "pinecone",
            description: "Pinecone API key (UUID-format, context-sensitive: PINECONE variable)",
            pattern: r#"(?i)(?:PINECONE_API_KEY|PINECONE_KEY)[\s]*[=:]["']?\s*(?P<body>[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})"#,
            min_entropy: 3.0,
        },
        // ── Weaviate ───────────────────────────────────────────────────────
        PatternDef {
            id: "weaviate-api-key-v1",
            provider: "weaviate",
            description: "Weaviate API key (X-Weaviate-Api-Key header or WEAVIATE_API_KEY env var)",
            pattern: r#"(?i)(?P<prefix>(?:X-Weaviate-Api-Key|WEAVIATE_API_KEY)[\s]*[:=]["']?\s*)(?P<body>[A-Za-z0-9+/=_-]{20,100})"#,
            min_entropy: 3.0,
        },
    ];

    defs.iter()
        .map(|def| {
            let regex = Regex::new(def.pattern).map_err(|source| AuditError::PatternCompile {
                id: def.id,
                source,
            })?;
            Ok(Pattern {
                id: def.id,
                provider: def.provider,
                description: def.description,
                regex,
                min_entropy: def.min_entropy,
            })
        })
        .collect()
}

/// Returns a filtered list of patterns given a comma-separated provider list.
/// If `providers` is empty, all patterns are returned.
///
/// # Errors
/// Returns `AuditError::Config` if any provider slug is not recognised.
pub fn filter_by_providers<'a>(
    patterns: &'a [Pattern],
    providers: &[String],
) -> Result<Vec<&'a Pattern>, AuditError> {
    if providers.is_empty() {
        return Ok(patterns.iter().collect());
    }

    // Collect the canonical slug set from the compiled patterns.
    let known: std::collections::HashSet<&str> =
        patterns.iter().map(|p| p.provider).collect();

    // Validate every requested provider before filtering.
    for requested in providers {
        if !known.contains(requested.as_str()) {
            let mut sorted: Vec<&str> = known.iter().copied().collect();
            sorted.sort_unstable();
            return Err(AuditError::Config(format!(
                "unknown provider '{}'. Valid providers: {}",
                requested,
                sorted.join(", ")
            )));
        }
    }

    // Exact-match filter.
    Ok(patterns
        .iter()
        .filter(|p| providers.iter().any(|l| p.provider == l.as_str()))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn patterns() -> Vec<Pattern> {
        build_patterns().expect("patterns must compile")
    }

    /// Helper: check whether `text` matches the pattern with the given id.
    fn matches(patterns: &[Pattern], id: &str, text: &str) -> bool {
        let p = patterns.iter().find(|p| p.id == id).unwrap_or_else(|| panic!("pattern {id} not found"));
        p.regex.is_match(text).unwrap_or(false)
    }

    // ── build patterns ──────────────────────────────────────────────────────

    #[test]
    fn all_patterns_compile() {
        let p = build_patterns();
        assert!(p.is_ok(), "patterns failed to compile: {:?}", p.err());
        assert!(p.unwrap().len() >= 18);
    }

    #[test]
    fn pattern_ids_are_unique() {
        let p = patterns();
        let mut ids: Vec<&str> = p.iter().map(|x| x.id).collect();
        ids.sort_unstable();
        let before = ids.len();
        ids.dedup();
        assert_eq!(before, ids.len(), "duplicate pattern ids detected");
    }

    // ── Anthropic ───────────────────────────────────────────────────────────

    #[test]
    fn anthropic_matches_valid_key() {
        let p = patterns();
        // 93 chars of base64url after the prefix (verified: 85 + 8 = 93)
        let key = format!("sk-ant-api03-{}", "xK9pQm7vL3nRwT5yJbHfDcGsEaZuViYo4W8MiNqX2PeUhCjBgFtOkRdSl1A6v0DwY_n-5mIT7QzHuWbEjcKaPabcdefgh");
        assert!(matches(&p, "anthropic-api-key-v1", &key), "should match valid Anthropic key");
    }

    #[test]
    fn anthropic_does_not_match_short_key() {
        let p = patterns();
        assert!(!matches(&p, "anthropic-api-key-v1", "sk-ant-api03-tooshort"));
    }

    #[test]
    fn anthropic_does_not_match_wrong_prefix() {
        let p = patterns();
        let body = "x".repeat(93);
        assert!(!matches(&p, "anthropic-api-key-v1", &format!("sk-ant-api04-{body}")));
    }

    // ── OpenAI project key ──────────────────────────────────────────────────

    #[test]
    fn openai_project_key_matches() {
        let p = patterns();
        let body = "A".repeat(120);
        assert!(matches(&p, "openai-project-key-v2", &format!("sk-proj-{body}")));
    }

    #[test]
    fn openai_project_key_no_match_short() {
        let p = patterns();
        assert!(!matches(&p, "openai-project-key-v2", "sk-proj-tooshort"));
    }

    // ── OpenAI legacy key ───────────────────────────────────────────────────

    #[test]
    fn openai_legacy_key_matches() {
        let p = patterns();
        let body = "xK9pQm7vL3nRwT5yJbHfDcGsEaZuViYo4W8MiNqX2Pe5AbcD";
        assert_eq!(body.len(), 48);
        assert!(matches(&p, "openai-legacy-key-v1", &format!("sk-{body} ")));
    }

    #[test]
    fn openai_legacy_does_not_match_proj_prefix() {
        let p = patterns();
        // sk-proj-... should only match openai-project-key-v2, not legacy
        let body = "A".repeat(120);
        assert!(!matches(&p, "openai-legacy-key-v1", &format!("sk-proj-{body}")));
    }

    #[test]
    fn openai_legacy_does_not_match_ant_prefix() {
        let p = patterns();
        let body = "x".repeat(48);
        assert!(!matches(&p, "openai-legacy-key-v1", &format!("sk-ant-api03-{body}")));
    }

    // ── OpenRouter ──────────────────────────────────────────────────────────

    #[test]
    fn openrouter_key_matches() {
        let p = patterns();
        let body = "aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2uV3wX4yZ5aB3cD4eF5g";
        assert!(matches(&p, "openrouter-api-key-v1", &format!("sk-or-{body}")));
    }

    #[test]
    fn openrouter_key_v1_prefix_matches() {
        let p = patterns();
        let body = "aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2uV3wX4yZ5aB3cD4eF5g";
        assert!(matches(&p, "openrouter-api-key-v1", &format!("sk-or-v1-{body}")));
    }

    // ── Google Gemini ───────────────────────────────────────────────────────

    #[test]
    fn google_gemini_key_matches() {
        let p = patterns();
        let body = "SyT7uV8wX9yZ0aB1cD2eF3gH4iJ5kL6mN7o";
        assert_eq!(body.len(), 35); // verified: 35 chars
        assert!(matches(&p, "google-gemini-key-v1", &format!("AIza{body}")));
    }

    #[test]
    fn google_gemini_no_match_wrong_prefix() {
        let p = patterns();
        let body = "S".repeat(35);
        assert!(!matches(&p, "google-gemini-key-v1", &format!("AIzb{body}")));
    }

    #[test]
    fn google_gemini_no_match_short_body() {
        let p = patterns();
        assert!(!matches(&p, "google-gemini-key-v1", "AIzaShort"));
    }

    // ── Google Vertex AI Service Account ────────────────────────────────────

    #[test]
    fn vertex_service_account_matches() {
        let p = patterns();
        let json = r#"{"type": "service_account", "project_id": "my-project", "private_key_id": "abc123def456abc123def456abc123def456abc1"}"#;
        assert!(matches(&p, "google-vertex-service-account-v1", json));
    }

    #[test]
    fn vertex_service_account_no_match_without_private_key_id() {
        let p = patterns();
        let json = r#"{"type": "service_account", "project_id": "my-project"}"#;
        assert!(!matches(&p, "google-vertex-service-account-v1", json));
    }

    // ── AWS Bedrock ─────────────────────────────────────────────────────────

    #[test]
    fn aws_akia_matches() {
        let p = patterns();
        assert!(matches(&p, "aws-access-key-id-v1", "AKIAIOSFODNN7EXAMPLE"));
    }

    #[test]
    fn aws_asia_matches() {
        let p = patterns();
        assert!(matches(&p, "aws-access-key-id-v1", "ASIAIOSFODNN7EXAMPLE"));
    }

    #[test]
    fn aws_no_match_wrong_prefix() {
        let p = patterns();
        assert!(!matches(&p, "aws-access-key-id-v1", "AKIBIOSFODNN7EXAMPLE"));
    }

    #[test]
    fn aws_no_match_too_short() {
        let p = patterns();
        assert!(!matches(&p, "aws-access-key-id-v1", "AKIA1234SHORT"));
    }

    // ── Azure OpenAI ────────────────────────────────────────────────────────

    #[test]
    fn azure_openai_matches_header_format() {
        let p = patterns();
        assert!(matches(
            &p,
            "azure-openai-subscription-key-v1",
            "Ocp-Apim-Subscription-Key: 1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d"
        ));
    }

    #[test]
    fn azure_openai_matches_equals_assignment() {
        let p = patterns();
        assert!(matches(
            &p,
            "azure-openai-subscription-key-v1",
            "Ocp-Apim-Subscription-Key=1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d"
        ));
    }

    #[test]
    fn azure_openai_no_match_without_context() {
        let p = patterns();
        // A standalone 32-hex string without the header context should NOT match
        assert!(!matches(
            &p,
            "azure-openai-subscription-key-v1",
            "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d"
        ));
    }

    // ── Cohere ──────────────────────────────────────────────────────────────

    #[test]
    fn cohere_key_matches() {
        let p = patterns();
        let body = "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0";
        assert!(matches(&p, "cohere-api-key-v1", &format!("co-{body}")));
    }

    #[test]
    fn cohere_no_match_short_body() {
        let p = patterns();
        assert!(!matches(&p, "cohere-api-key-v1", "co-short"));
    }

    // ── Mistral AI ──────────────────────────────────────────────────────────

    #[test]
    fn mistral_key_matches() {
        let p = patterns();
        let body = "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0";
        assert!(matches(&p, "mistral-api-key-v1", &format!("mi-{body}")));
    }

    #[test]
    fn mistral_no_match_short_body() {
        let p = patterns();
        assert!(!matches(&p, "mistral-api-key-v1", "mi-short"));
    }

    // ── Hugging Face ────────────────────────────────────────────────────────

    #[test]
    fn huggingface_token_matches() {
        let p = patterns();
        let body = "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9";
        assert_eq!(body.len(), 38);
        assert!(matches(&p, "huggingface-token-v1", &format!("hf_{body}")));
    }

    #[test]
    fn huggingface_no_match_short() {
        let p = patterns();
        assert!(!matches(&p, "huggingface-token-v1", "hf_short"));
    }

    // ── Replicate ───────────────────────────────────────────────────────────

    #[test]
    fn replicate_token_matches() {
        let p = patterns();
        let body = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
        assert_eq!(body.len(), 40);
        assert!(matches(&p, "replicate-api-token-v1", &format!("r8_{body}")));
    }

    #[test]
    fn replicate_no_match_non_hex_body() {
        let p = patterns();
        // body must be hex; 'g' is not hex
        let body = "g1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
        assert!(!matches(&p, "replicate-api-token-v1", &format!("r8_{body}")));
    }

    // ── Together AI ─────────────────────────────────────────────────────────

    #[test]
    fn together_ai_matches_env_var() {
        let p = patterns();
        let key = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
        assert!(matches(&p, "together-ai-key-v1", &format!("TOGETHER_API_KEY={key}")));
    }

    #[test]
    fn together_ai_no_match_without_context() {
        let p = patterns();
        // A bare 40-char hex should NOT match (needs context)
        let key = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
        assert!(!matches(&p, "together-ai-key-v1", key));
    }

    // ── Groq ────────────────────────────────────────────────────────────────

    #[test]
    fn groq_key_matches() {
        let p = patterns();
        let body = "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0U1v2W3x4Y5z6";
        assert_eq!(body.len(), 52);
        assert!(matches(&p, "groq-api-key-v1", &format!("gsk_{body}")));
    }

    #[test]
    fn groq_live_prefix_matches() {
        let p = patterns();
        let body = "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0U1v2W3x4Y5z6";
        assert!(matches(&p, "groq-api-key-v1", &format!("gsk_live_{body}")));
    }

    #[test]
    fn groq_no_match_short_body() {
        let p = patterns();
        assert!(!matches(&p, "groq-api-key-v1", "gsk_short"));
    }

    // ── Perplexity ──────────────────────────────────────────────────────────

    #[test]
    fn perplexity_key_matches() {
        let p = patterns();
        let body = "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0U1v2W3x4Y5z6";
        assert_eq!(body.len(), 52);
        // 48 chars required — use exactly 48
        let body48 = "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0U1v2W3x4";
        assert_eq!(body48.len(), 48);
        assert!(matches(&p, "perplexity-key-v1", &format!("pplx-{body48}")));
    }

    #[test]
    fn perplexity_no_match_short() {
        let p = patterns();
        assert!(!matches(&p, "perplexity-key-v1", "pplx-short"));
    }

    // ── ElevenLabs ──────────────────────────────────────────────────────────

    #[test]
    fn elevenlabs_xi_header_matches() {
        let p = patterns();
        assert!(matches(
            &p,
            "elevenlabs-api-key-v1",
            "xi-api-key: 1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d"
        ));
    }

    #[test]
    fn elevenlabs_env_var_matches() {
        let p = patterns();
        assert!(matches(
            &p,
            "elevenlabs-api-key-v1",
            "ELEVENLABS_API_KEY=1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d"
        ));
    }

    #[test]
    fn elevenlabs_no_match_standalone_hex() {
        let p = patterns();
        assert!(!matches(
            &p,
            "elevenlabs-api-key-v1",
            "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d"
        ));
    }

    // ── Pinecone ────────────────────────────────────────────────────────────

    #[test]
    fn pinecone_key_matches() {
        let p = patterns();
        assert!(matches(
            &p,
            "pinecone-api-key-v1",
            "PINECONE_API_KEY=12345678-1234-1234-1234-123456789abc"
        ));
    }

    #[test]
    fn pinecone_no_match_uuid_without_context() {
        let p = patterns();
        // UUID without context should NOT match (prevents false positives)
        assert!(!matches(
            &p,
            "pinecone-api-key-v1",
            "12345678-1234-1234-1234-123456789abc"
        ));
    }

    // ── Weaviate ────────────────────────────────────────────────────────────

    #[test]
    fn weaviate_header_matches() {
        let p = patterns();
        assert!(matches(
            &p,
            "weaviate-api-key-v1",
            "X-Weaviate-Api-Key: SomeReallyLongApiKeyValueHere1234567890"
        ));
    }

    #[test]
    fn weaviate_env_var_matches() {
        let p = patterns();
        assert!(matches(
            &p,
            "weaviate-api-key-v1",
            "WEAVIATE_API_KEY=SomeReallyLongApiKeyValueHere1234567890"
        ));
    }

    // ── filter_by_providers ─────────────────────────────────────────────────

    #[test]
    fn filter_empty_returns_all() {
        let p = patterns();
        let result = filter_by_providers(&p, &[]).unwrap();
        assert_eq!(result.len(), p.len());
    }

    #[test]
    fn filter_single_provider() {
        let p = patterns();
        let result = filter_by_providers(&p, &["openai".to_string()]).unwrap();
        assert!(result.iter().all(|pat| pat.provider == "openai"));
        assert!(!result.is_empty());
    }

    #[test]
    fn filter_multiple_providers() {
        let p = patterns();
        let result = filter_by_providers(&p, &["openai".to_string(), "anthropic".to_string()]).unwrap();
        assert!(result.iter().all(|pat| pat.provider == "openai" || pat.provider == "anthropic"));
    }

    #[test]
    fn filter_unknown_provider_returns_error() {
        let p = patterns();
        let result = filter_by_providers(&p, &["bogusprovider".to_string()]);
        assert!(result.is_err(), "unknown provider must return an error");
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("bogusprovider"), "error must name the bad provider");
    }

    #[test]
    fn pattern_debug_impl_includes_id_and_provider() {
        let p = patterns();
        let s = format!("{:?}", p[0]);
        assert!(s.contains("Pattern"), "Debug output should contain 'Pattern': {s}");
        assert!(s.contains("id"), "Debug output should contain 'id': {s}");
        assert!(s.contains("provider"), "Debug output should contain 'provider': {s}");
    }
}
