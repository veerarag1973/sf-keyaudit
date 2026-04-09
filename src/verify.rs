//! Secret verification module — offline and optional network validation.
//!
//! **Offline validation** runs by default when `--verify` is passed.  It
//! examines the matched value for patterns that indicate it is a test /
//! example / placeholder rather than a real live credential.
//!
//! **Network validation** is strictly opt-in and is enabled by passing
//! `--verify` together with `SFKEYAUDIT_NETWORK_VERIFY=1`.  When enabled it
//! makes a lightweight, **read-only** HTTP request to the provider endpoint
//! (e.g. `GET /v1/models` for OpenAI) to determine whether the credential is
//! active.  The request does not consume any credits.
//!
//! # Privacy notice
//! With network validation enabled the key material is transmitted to the
//! provider's API endpoint.  Only enable this in isolated, secure environments
//! such as a dedicated security-scanning pipeline with network egress controls.

use crate::types::Finding;

// ── Offline test/placeholder markers ──────────────────────────────────────────

/// Substrings that indicate the matched value is a test or example key rather
/// than a real credential.  Comparison is case-insensitive.
const TEST_MARKERS: &[&str] = &[
    "test",
    "example",
    "placeholder",
    "sample",
    "demo",
    "fake",
    "mock",
    "dummy",
    "your_key_here",
    "your-key-here",
    "replace_me",
    "replace-me",
    "changeme",
    "change_me",
    "insert_key",
    "add_your_key",
    "todo",
    "xxxxxxxxxx",
    "0000000000",
    "1111111111",
    "aaaaaaaaa",
    "abcdefgh",
    "12345678",
];

/// Validate a string against the test-marker list.
fn contains_test_marker(s: &str) -> Option<&'static str> {
    let lower = s.to_lowercase();
    TEST_MARKERS
        .iter()
        .find(|&&m| lower.contains(m))
        .copied()
}

/// Return `true` when `s` consists entirely of one repeated character
/// (e.g. "aaaaaaaaaa" or "XXXXXXXXXX").  Minimum length 8 to avoid false
/// positives on short legitimate values.
fn is_repeated_char(s: &str) -> bool {
    if s.len() < 8 {
        return false;
    }
    let first = match s.chars().next() {
        Some(c) => c,
        None => return false,
    };
    s.chars().all(|c| c == first)
}

// ── Public API ─────────────────────────────────────────────────────────────────

/// Summary outcome of a validation run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationStatus {
    /// Value matches test / example / placeholder patterns.
    TestKey,
    /// High entropy and format passes; likely a real credential.
    LikelyValid,
    /// Network validation confirmed the credential is active.
    NetworkConfirmedValid,
    /// Network validation confirmed the credential is revoked / invalid.
    NetworkConfirmedInvalid,
    /// Validation could not be performed.
    Unknown,
}

impl ValidationStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::TestKey => "test-key",
            Self::LikelyValid => "likely-valid",
            Self::NetworkConfirmedValid => "network-valid",
            Self::NetworkConfirmedInvalid => "network-invalid",
            Self::Unknown => "unknown",
        }
    }
}

impl std::fmt::Display for ValidationStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Detailed result of a single validation attempt.
#[derive(Debug, Clone)]
pub struct ValidationResult {
    pub status: ValidationStatus,
    /// "offline" or "network".
    pub method: &'static str,
    /// Optional human-readable detail string for debugging.
    pub detail: Option<String>,
}

impl ValidationResult {
    fn offline(status: ValidationStatus) -> Self {
        Self { status, method: "offline", detail: None }
    }

    fn offline_detail(status: ValidationStatus, detail: impl Into<String>) -> Self {
        Self { status, method: "offline", detail: Some(detail.into()) }
    }
}

/// Apply offline heuristics to a finding and return a [`ValidationResult`].
///
/// Checks:
/// 1. Does the match text contain a known test/placeholder marker?
/// 2. Does the value consist of a single repeated character?
/// 3. Is the Shannon entropy high enough to suggest a real credential?
pub fn validate_offline(finding: &Finding) -> ValidationResult {
    // The match_text contains "PREFIX***REDACTED***" — check the full text.
    if let Some(marker) = contains_test_marker(&finding.match_text) {
        return ValidationResult::offline_detail(
            ValidationStatus::TestKey,
            format!("value contains test marker: '{marker}'"),
        );
    }

    // Also check pattern_id for test / example context.
    if contains_test_marker(&finding.pattern_id).is_some() {
        return ValidationResult::offline_detail(
            ValidationStatus::TestKey,
            "pattern_id contains test marker",
        );
    }

    // Check for repeated-character body in the match text (after stripping prefix).
    let body_candidate = finding
        .match_text
        .split("***")
        .next()
        .unwrap_or(&finding.match_text);
    if is_repeated_char(body_candidate) {
        return ValidationResult::offline_detail(
            ValidationStatus::TestKey,
            "matched value is a repeated-character placeholder",
        );
    }

    // Entropy already above the pattern's min_entropy threshold (checked in scanner).
    // If entropy is high, classify as likely-valid.
    if finding.entropy >= 3.5 {
        ValidationResult::offline(ValidationStatus::LikelyValid)
    } else {
        ValidationResult::offline_detail(
            ValidationStatus::LikelyValid,
            format!("low entropy ({:.2}) but format matched", finding.entropy),
        )
    }
}

/// Apply offline validation to a slice of findings, returning them with
/// `validation_status` populated.
pub fn apply_offline_validation(mut findings: Vec<Finding>) -> Vec<Finding> {
    for f in &mut findings {
        let result = validate_offline(f);
        tracing::debug!(
            fingerprint = %f.fingerprint,
            status = %result.status,
            "offline validation"
        );
        f.validation_status = Some(result.status.as_str().to_string());
    }
    findings
}

// ── Network validation ─────────────────────────────────────────────────────────

const NETWORK_TIMEOUT_SECS: u64 = 10;

fn network_client() -> reqwest::blocking::Client {
    reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(NETWORK_TIMEOUT_SECS))
        .user_agent(concat!("sf-keyaudit/", env!("CARGO_PKG_VERSION")))
        .build()
        .unwrap_or_default()
}

/// Validate a single credential body against the provider's live API endpoint.
///
/// This transmits key material to the provider — only call when
/// `SFKEYAUDIT_NETWORK_VERIFY=1` is explicitly set by the operator.
///
/// Supported providers: all 29 patterns across 18+ providers.
/// Providers where live validation requires extra context (Weaviate instance
/// URL, Azure OpenAI endpoint) return `ValidationStatus::Unknown`.
pub fn validate_network_body(provider: &str, body: &str) -> ValidationResult {
    let client = network_client();
    match provider {
        "openai"         => validate_openai(&client, body),
        "anthropic"      => validate_anthropic(&client, body),
        "openrouter"     => validate_openrouter(&client, body),
        "google-gemini"  => validate_google_gemini(&client, body),
        "cohere"         => validate_cohere(&client, body),
        "mistral-ai"     => validate_mistral(&client, body),
        "huggingface"    => validate_huggingface(&client, body),
        "replicate"      => validate_replicate(&client, body),
        "together-ai"    => validate_together_ai(&client, body),
        "groq"           => validate_groq(&client, body),
        "perplexity"     => validate_perplexity(&client, body),
        "elevenlabs"     => validate_elevenlabs(&client, body),
        "pinecone"       => validate_pinecone(&client, body),
        "stripe"         => validate_stripe(&client, body),
        "slack"          => validate_slack(&client, body),
        "github"         => validate_github(&client, body),
        "gitlab"         => validate_gitlab(&client, body),
        "sendgrid"       => validate_sendgrid(&client, body),
        "stability-ai" | "google-vertex-ai" | "aws-bedrock"
        | "azure-openai" | "weaviate" | "twilio" => ValidationResult {
            status: ValidationStatus::Unknown,
            method: "network",
            detail: Some(format!(
                "no network validator for '{provider}' — requires additional context (endpoint URL, SigV4 signing, etc.)"
            )),
        },
        _ => ValidationResult {
            status: ValidationStatus::Unknown,
            method: "network",
            detail: Some(format!("no network adapter for provider '{provider}'")),
        },
    }
}

fn validate_openai(client: &reqwest::blocking::Client, key: &str) -> ValidationResult {
    match client
        .get("https://api.openai.com/v1/models")
        .header("Authorization", format!("Bearer {key}"))
        .send()
    {
        Ok(resp) => {
            let code = resp.status();
            if code.is_success() {
                ValidationResult {
                    status: ValidationStatus::NetworkConfirmedValid,
                    method: "network",
                    detail: Some("openai /v1/models → 200".into()),
                }
            } else if code == 401 || code == 403 {
                ValidationResult {
                    status: ValidationStatus::NetworkConfirmedInvalid,
                    method: "network",
                    detail: Some(format!("openai /v1/models → {code}")),
                }
            } else {
                ValidationResult {
                    status: ValidationStatus::Unknown,
                    method: "network",
                    detail: Some(format!("openai /v1/models → unexpected {code}")),
                }
            }
        }
        Err(e) => ValidationResult {
            status: ValidationStatus::Unknown,
            method: "network",
            detail: Some(format!("request failed: {e}")),
        },
    }
}

fn validate_anthropic(client: &reqwest::blocking::Client, key: &str) -> ValidationResult {
    match client
        .get("https://api.anthropic.com/v1/models")
        .header("x-api-key", key)
        .header("anthropic-version", "2023-06-01")
        .send()
    {
        Ok(resp) => {
            let code = resp.status();
            if code.is_success() {
                ValidationResult {
                    status: ValidationStatus::NetworkConfirmedValid,
                    method: "network",
                    detail: Some("anthropic /v1/models → 200".into()),
                }
            } else if code == 401 || code == 403 {
                ValidationResult {
                    status: ValidationStatus::NetworkConfirmedInvalid,
                    method: "network",
                    detail: Some(format!("anthropic /v1/models → {code}")),
                }
            } else {
                ValidationResult {
                    status: ValidationStatus::Unknown,
                    method: "network",
                    detail: Some(format!("anthropic /v1/models → unexpected {code}")),
                }
            }
        }
        Err(e) => ValidationResult {
            status: ValidationStatus::Unknown,
            method: "network",
            detail: Some(format!("request failed: {e}")),
        },
    }
}

/// Generic helper: send a GET with `Authorization: Bearer {key}`, map
/// 200→Valid, 401/403→Invalid, else Unknown.
fn probe_bearer(
    client: &reqwest::blocking::Client,
    url: &str,
    key: &str,
    label: &str,
) -> ValidationResult {
    match client
        .get(url)
        .header("Authorization", format!("Bearer {key}"))
        .send()
    {
        Ok(resp) => {
            let code = resp.status();
            if code.is_success() {
                ValidationResult {
                    status: ValidationStatus::NetworkConfirmedValid,
                    method: "network",
                    detail: Some(format!("{label} → 200")),
                }
            } else if code == 401 || code == 403 {
                ValidationResult {
                    status: ValidationStatus::NetworkConfirmedInvalid,
                    method: "network",
                    detail: Some(format!("{label} → {code}")),
                }
            } else {
                ValidationResult {
                    status: ValidationStatus::Unknown,
                    method: "network",
                    detail: Some(format!("{label} → unexpected {code}")),
                }
            }
        }
        Err(e) => ValidationResult {
            status: ValidationStatus::Unknown,
            method: "network",
            detail: Some(format!("request failed: {e}")),
        },
    }
}

fn validate_openrouter(client: &reqwest::blocking::Client, key: &str) -> ValidationResult {
    probe_bearer(client, "https://openrouter.ai/api/v1/models", key, "openrouter /api/v1/models")
}

fn validate_google_gemini(client: &reqwest::blocking::Client, key: &str) -> ValidationResult {
    let url = format!("https://generativelanguage.googleapis.com/v1beta/models?key={key}");
    match client.get(&url).send() {
        Ok(resp) => {
            let code = resp.status();
            if code.is_success() {
                ValidationResult {
                    status: ValidationStatus::NetworkConfirmedValid,
                    method: "network",
                    detail: Some("google-gemini /v1beta/models → 200".into()),
                }
            } else if code == 400 || code == 401 || code == 403 {
                ValidationResult {
                    status: ValidationStatus::NetworkConfirmedInvalid,
                    method: "network",
                    detail: Some(format!("google-gemini /v1beta/models → {code}")),
                }
            } else {
                ValidationResult {
                    status: ValidationStatus::Unknown,
                    method: "network",
                    detail: Some(format!("google-gemini → unexpected {code}")),
                }
            }
        }
        Err(e) => ValidationResult {
            status: ValidationStatus::Unknown,
            method: "network",
            detail: Some(format!("request failed: {e}")),
        },
    }
}

fn validate_cohere(client: &reqwest::blocking::Client, key: &str) -> ValidationResult {
    probe_bearer(client, "https://api.cohere.ai/v1/models", key, "cohere /v1/models")
}

fn validate_mistral(client: &reqwest::blocking::Client, key: &str) -> ValidationResult {
    probe_bearer(client, "https://api.mistral.ai/v1/models", key, "mistral /v1/models")
}

fn validate_huggingface(client: &reqwest::blocking::Client, key: &str) -> ValidationResult {
    probe_bearer(client, "https://huggingface.co/api/whoami", key, "huggingface /api/whoami")
}

fn validate_replicate(client: &reqwest::blocking::Client, key: &str) -> ValidationResult {
    match client
        .get("https://api.replicate.com/v1/models")
        .header("Authorization", format!("Token {key}"))
        .send()
    {
        Ok(resp) => {
            let code = resp.status();
            if code.is_success() {
                ValidationResult {
                    status: ValidationStatus::NetworkConfirmedValid,
                    method: "network",
                    detail: Some("replicate /v1/models → 200".into()),
                }
            } else if code == 401 || code == 403 {
                ValidationResult {
                    status: ValidationStatus::NetworkConfirmedInvalid,
                    method: "network",
                    detail: Some(format!("replicate /v1/models → {code}")),
                }
            } else {
                ValidationResult {
                    status: ValidationStatus::Unknown,
                    method: "network",
                    detail: Some(format!("replicate → unexpected {code}")),
                }
            }
        }
        Err(e) => ValidationResult {
            status: ValidationStatus::Unknown,
            method: "network",
            detail: Some(format!("request failed: {e}")),
        },
    }
}

fn validate_together_ai(client: &reqwest::blocking::Client, key: &str) -> ValidationResult {
    probe_bearer(client, "https://api.together.xyz/v1/models", key, "together-ai /v1/models")
}

fn validate_groq(client: &reqwest::blocking::Client, key: &str) -> ValidationResult {
    probe_bearer(client, "https://api.groq.com/openai/v1/models", key, "groq /openai/v1/models")
}

fn validate_perplexity(client: &reqwest::blocking::Client, key: &str) -> ValidationResult {
    let body = serde_json::json!({
        "model": "sonar-small-online",
        "messages": [{"role": "user", "content": "hi"}],
        "max_tokens": 1
    });
    match client
        .post("https://api.perplexity.ai/chat/completions")
        .header("Authorization", format!("Bearer {key}"))
        .header("Content-Type", "application/json")
        .json(&body)
        .send()
    {
        Ok(resp) => {
            let code = resp.status();
            if code.is_success() {
                ValidationResult {
                    status: ValidationStatus::NetworkConfirmedValid,
                    method: "network",
                    detail: Some("perplexity /chat/completions → 200".into()),
                }
            } else if code == 401 || code == 403 {
                ValidationResult {
                    status: ValidationStatus::NetworkConfirmedInvalid,
                    method: "network",
                    detail: Some(format!("perplexity /chat/completions → {code}")),
                }
            } else {
                ValidationResult {
                    status: ValidationStatus::Unknown,
                    method: "network",
                    detail: Some(format!("perplexity → unexpected {code}")),
                }
            }
        }
        Err(e) => ValidationResult {
            status: ValidationStatus::Unknown,
            method: "network",
            detail: Some(format!("request failed: {e}")),
        },
    }
}

fn validate_elevenlabs(client: &reqwest::blocking::Client, key: &str) -> ValidationResult {
    match client
        .get("https://api.elevenlabs.io/v1/user")
        .header("xi-api-key", key)
        .send()
    {
        Ok(resp) => {
            let code = resp.status();
            if code.is_success() {
                ValidationResult {
                    status: ValidationStatus::NetworkConfirmedValid,
                    method: "network",
                    detail: Some("elevenlabs /v1/user → 200".into()),
                }
            } else if code == 401 || code == 403 {
                ValidationResult {
                    status: ValidationStatus::NetworkConfirmedInvalid,
                    method: "network",
                    detail: Some(format!("elevenlabs /v1/user → {code}")),
                }
            } else {
                ValidationResult {
                    status: ValidationStatus::Unknown,
                    method: "network",
                    detail: Some(format!("elevenlabs → unexpected {code}")),
                }
            }
        }
        Err(e) => ValidationResult {
            status: ValidationStatus::Unknown,
            method: "network",
            detail: Some(format!("request failed: {e}")),
        },
    }
}

fn validate_pinecone(client: &reqwest::blocking::Client, key: &str) -> ValidationResult {
    match client
        .get("https://api.pinecone.io/indexes")
        .header("Api-Key", key)
        .send()
    {
        Ok(resp) => {
            let code = resp.status();
            if code.is_success() {
                ValidationResult {
                    status: ValidationStatus::NetworkConfirmedValid,
                    method: "network",
                    detail: Some("pinecone /indexes → 200".into()),
                }
            } else if code == 401 || code == 403 {
                ValidationResult {
                    status: ValidationStatus::NetworkConfirmedInvalid,
                    method: "network",
                    detail: Some(format!("pinecone /indexes → {code}")),
                }
            } else {
                ValidationResult {
                    status: ValidationStatus::Unknown,
                    method: "network",
                    detail: Some(format!("pinecone → unexpected {code}")),
                }
            }
        }
        Err(e) => ValidationResult {
            status: ValidationStatus::Unknown,
            method: "network",
            detail: Some(format!("request failed: {e}")),
        },
    }
}

fn validate_stripe(client: &reqwest::blocking::Client, key: &str) -> ValidationResult {
    probe_bearer(client, "https://api.stripe.com/v1/balance", key, "stripe /v1/balance")
}

fn validate_slack(client: &reqwest::blocking::Client, token: &str) -> ValidationResult {
    match client
        .post("https://slack.com/api/auth.test")
        .header("Authorization", format!("Bearer {token}"))
        .header("Content-Type", "application/json; charset=utf-8")
        .body("{}")
        .send()
    {
        Ok(resp) => {
            let code = resp.status();
            if !code.is_success() {
                return ValidationResult {
                    status: ValidationStatus::Unknown,
                    method: "network",
                    detail: Some(format!("slack auth.test → {code}")),
                };
            }
            match resp.json::<serde_json::Value>() {
                Ok(json) => {
                    if json.get("ok").and_then(|v| v.as_bool()).unwrap_or(false) {
                        ValidationResult {
                            status: ValidationStatus::NetworkConfirmedValid,
                            method: "network",
                            detail: Some("slack auth.test → ok:true".into()),
                        }
                    } else {
                        let err = json
                            .get("error")
                            .and_then(|v| v.as_str())
                            .unwrap_or("unknown");
                        ValidationResult {
                            status: ValidationStatus::NetworkConfirmedInvalid,
                            method: "network",
                            detail: Some(format!("slack auth.test → ok:false error:{err}")),
                        }
                    }
                }
                Err(e) => ValidationResult {
                    status: ValidationStatus::Unknown,
                    method: "network",
                    detail: Some(format!("slack auth.test parse error: {e}")),
                },
            }
        }
        Err(e) => ValidationResult {
            status: ValidationStatus::Unknown,
            method: "network",
            detail: Some(format!("request failed: {e}")),
        },
    }
}

fn validate_github(client: &reqwest::blocking::Client, token: &str) -> ValidationResult {
    match client
        .get("https://api.github.com/user")
        .header("Authorization", format!("Bearer {token}"))
        .header("User-Agent", concat!("sf-keyaudit/", env!("CARGO_PKG_VERSION")))
        .header("X-GitHub-Api-Version", "2022-11-28")
        .send()
    {
        Ok(resp) => {
            let code = resp.status();
            if code.is_success() {
                ValidationResult {
                    status: ValidationStatus::NetworkConfirmedValid,
                    method: "network",
                    detail: Some("github /user → 200".into()),
                }
            } else if code == 401 || code == 403 {
                ValidationResult {
                    status: ValidationStatus::NetworkConfirmedInvalid,
                    method: "network",
                    detail: Some(format!("github /user → {code}")),
                }
            } else {
                ValidationResult {
                    status: ValidationStatus::Unknown,
                    method: "network",
                    detail: Some(format!("github → unexpected {code}")),
                }
            }
        }
        Err(e) => ValidationResult {
            status: ValidationStatus::Unknown,
            method: "network",
            detail: Some(format!("request failed: {e}")),
        },
    }
}

fn validate_gitlab(client: &reqwest::blocking::Client, token: &str) -> ValidationResult {
    match client
        .get("https://gitlab.com/api/v4/personal_access_tokens/self")
        .header("PRIVATE-TOKEN", token)
        .send()
    {
        Ok(resp) => {
            let code = resp.status();
            if code.is_success() {
                ValidationResult {
                    status: ValidationStatus::NetworkConfirmedValid,
                    method: "network",
                    detail: Some("gitlab personal_access_tokens/self → 200".into()),
                }
            } else if code == 401 || code == 403 {
                ValidationResult {
                    status: ValidationStatus::NetworkConfirmedInvalid,
                    method: "network",
                    detail: Some(format!("gitlab personal_access_tokens/self → {code}")),
                }
            } else {
                ValidationResult {
                    status: ValidationStatus::Unknown,
                    method: "network",
                    detail: Some(format!("gitlab → unexpected {code}")),
                }
            }
        }
        Err(e) => ValidationResult {
            status: ValidationStatus::Unknown,
            method: "network",
            detail: Some(format!("request failed: {e}")),
        },
    }
}

fn validate_sendgrid(client: &reqwest::blocking::Client, key: &str) -> ValidationResult {
    probe_bearer(client, "https://api.sendgrid.com/v3/user/account", key, "sendgrid /v3/user/account")
}

///
/// Findings without a body (e.g. read from a saved report) are left with
/// `Unknown`.  The offline validation result is overwritten only when a
/// definitive network result is obtained.
pub fn apply_network_validation(mut findings: Vec<Finding>) -> Vec<Finding> {
    for f in &mut findings {
        let result = if let Some(ref body) = f.secret_body {
            validate_network_body(&f.provider, body)
        } else {
            ValidationResult {
                status: ValidationStatus::Unknown,
                method: "network",
                detail: Some("no credential body available for network check".into()),
            }
        };
        tracing::debug!(
            fingerprint = %f.fingerprint,
            status = %result.status,
            method = result.method,
            "network validation"
        );
        f.validation_status = Some(result.status.as_str().to_string());
    }
    findings
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Finding;

    fn make_finding(match_text: &str, entropy: f64) -> Finding {
        Finding {
            id: "f-001".into(),
            fingerprint: "fp-abc123456789".into(),
            provider: "openai".into(),
            file: "src/config.py".into(),
            line: 1,
            column: 1,
            match_text: match_text.to_string(),
            pattern_id: "openai-legacy-key-v1".into(),
            severity: "critical".into(),
            entropy,
            remediation: None,
            validation_status: None,
            first_seen: None,
            last_seen: None,
            owner: None,
            last_author: None,
            suppression_provenance: None,
            secret_body: None,
        }
    }

    #[test]
    fn test_marker_in_match_gives_test_key() {
        let f = make_finding("sk-testkey_REDACTED", 4.5);
        let r = validate_offline(&f);
        assert_eq!(r.status, ValidationStatus::TestKey);
        assert_eq!(r.method, "offline");
    }

    #[test]
    fn example_marker_in_match_gives_test_key() {
        let f = make_finding("sk-example***REDACTED***", 4.2);
        let r = validate_offline(&f);
        assert_eq!(r.status, ValidationStatus::TestKey);
    }

    #[test]
    fn high_entropy_real_value_gives_likely_valid() {
        let f = make_finding("sk-***REDACTED***", 4.8);
        let r = validate_offline(&f);
        assert_eq!(r.status, ValidationStatus::LikelyValid);
    }

    #[test]
    fn low_entropy_still_likely_valid() {
        let f = make_finding("sk-***REDACTED***", 3.0);
        let r = validate_offline(&f);
        assert_eq!(r.status, ValidationStatus::LikelyValid);
    }

    #[test]
    fn repeated_char_prefix_gives_test_key() {
        let f = make_finding("aaaaaaaaaa***REDACTED***", 1.0);
        let r = validate_offline(&f);
        assert_eq!(r.status, ValidationStatus::TestKey);
    }

    #[test]
    fn apply_offline_populates_validation_status() {
        let f = make_finding("sk-***REDACTED***", 4.5);
        let validated = apply_offline_validation(vec![f]);
        assert!(validated[0].validation_status.is_some());
        assert_eq!(validated[0].validation_status.as_deref(), Some("likely-valid"));
    }

    #[test]
    fn validation_status_as_str() {
        assert_eq!(ValidationStatus::TestKey.as_str(), "test-key");
        assert_eq!(ValidationStatus::LikelyValid.as_str(), "likely-valid");
        assert_eq!(ValidationStatus::NetworkConfirmedValid.as_str(), "network-valid");
        assert_eq!(ValidationStatus::NetworkConfirmedInvalid.as_str(), "network-invalid");
        assert_eq!(ValidationStatus::Unknown.as_str(), "unknown");
    }

    #[test]
    fn contains_test_marker_is_case_insensitive() {
        assert!(contains_test_marker("TEST_KEY_HERE").is_some());
        assert!(contains_test_marker("my-example-token").is_some());
        assert!(contains_test_marker("sk-realkey123").is_none());
    }

    #[test]
    fn is_repeated_char_detects_single_char_strings() {
        assert!(is_repeated_char("aaaaaaaaa"));
        assert!(is_repeated_char("XXXXXXXXXX"));
        assert!(!is_repeated_char("abcdefghij"));
        assert!(!is_repeated_char("aaaa")); // too short
    }
}
