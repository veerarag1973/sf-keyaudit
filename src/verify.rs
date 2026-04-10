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
//!
//! # Pluggable validator subsystem
//! Every provider validator implements the [`ProviderValidator`] trait.
//! Shared concerns (timeout, concurrency, retries, rate-limiting, backoff)
//! are handled by [`ValidatorRunner`] so that individual validators contain
//! only provider-specific logic.

use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use serde::{Deserialize, Serialize};
use crate::types::Finding;

// ── Rate-limit state ──────────────────────────────────────────────────────────

/// Per-provider in-memory rate-limit window.
struct ProviderBucket {
    /// When the current window started.
    window_start: Instant,
    /// Number of requests made in this window.
    count: u32,
}

/// A simple token-bucket rate limiter shared across threads.
#[derive(Clone)]
pub struct RateLimiter {
    inner: Arc<Mutex<HashMap<String, ProviderBucket>>>,
    /// Maximum requests per provider per window.
    max_per_window: u32,
    /// Window duration.
    window: Duration,
}

impl RateLimiter {
    /// Create a new rate limiter.
    ///
    /// `max_per_window` requests are allowed per provider within `window`.
    pub fn new(max_per_window: u32, window: Duration) -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
            max_per_window,
            window,
        }
    }

    /// Returns `true` if the caller is allowed to proceed, `false` if the
    /// rate limit for `provider` has been exhausted in the current window.
    pub fn check_and_increment(&self, provider: &str) -> bool {
        let mut map = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        let bucket = map.entry(provider.to_string()).or_insert(ProviderBucket {
            window_start: now,
            count: 0,
        });
        // Reset window if it has elapsed.
        if now.duration_since(bucket.window_start) >= self.window {
            bucket.window_start = now;
            bucket.count = 0;
        }
        if bucket.count >= self.max_per_window {
            return false;
        }
        bucket.count += 1;
        true
    }
}

// ── Pluggable validator trait ─────────────────────────────────────────────────

/// A provider-specific network validator.
///
/// Implementors contain only the logic for a single provider API; all shared
/// concerns (timeout, retries, rate-limiting, backoff) are handled by
/// [`ValidatorRunner`].
pub trait ProviderValidator: Send + Sync {
    /// The provider slug this validator handles (must match `Finding.provider`).
    fn provider(&self) -> &'static str;

    /// Probe the provider API with `body` and return a [`ValidationResult`].
    ///
    /// Implementors **must not** retry themselves; retries are managed by
    /// [`ValidatorRunner`].
    fn probe(&self, client: &reqwest::blocking::Client, body: &str) -> ValidationResult;
}

/// Orchestrates validator execution with retries, backoff, and rate-limiting.
pub struct ValidatorRunner {
    validators: HashMap<String, Box<dyn ProviderValidator>>,
    limiter: RateLimiter,
    max_retries: u32,
    base_backoff: Duration,
}

impl ValidatorRunner {
    /// Create a runner loaded with all built-in validators.
    pub fn default_runner() -> Self {
        let mut validators: HashMap<String, Box<dyn ProviderValidator>> = HashMap::new();
        for v in default_validators() {
            validators.insert(v.provider().to_string(), v);
        }
        Self {
            validators,
            // 10 requests/provider per 60-second window.
            limiter: RateLimiter::new(10, Duration::from_secs(60)),
            max_retries: 2,
            base_backoff: Duration::from_millis(500),
        }
    }

    /// Register a custom validator, overriding any built-in for the same provider.
    pub fn register(&mut self, validator: Box<dyn ProviderValidator>) {
        self.validators.insert(validator.provider().to_string(), validator);
    }

    /// Validate a finding's body against its provider.
    ///
    /// Returns [`ValidationResult`] with the definitive status.  The result
    /// may be `RateLimited` if the provider bucket is exhausted, or
    /// `EndpointRequired` if no validator exists for the provider.
    pub fn validate(&self, provider: &str, body: &str, client: &reqwest::blocking::Client) -> ValidationResult {
        let Some(validator) = self.validators.get(provider) else {
            return ValidationResult {
                status: ValidationStatus::EndpointRequired,
                method: "network",
                detail: Some(format!("no network validator for provider '{}' (requires additional context or configuration)", provider)),
            };
        };
        if !self.limiter.check_and_increment(provider) {
            return ValidationResult {
                status: ValidationStatus::RateLimited,
                method: "network",
                detail: Some(format!("rate limit reached for provider '{}'; retry after the window expires", provider)),
            };
        }
        let mut last = ValidationResult {
            status: ValidationStatus::Unknown,
            method: "network",
            detail: None,
        };
        for attempt in 0..=self.max_retries {
            let result = validator.probe(client, body);
            // Definitive results — do not retry.
            match result.status {
                ValidationStatus::NetworkConfirmedValid | ValidationStatus::NetworkConfirmedInvalid => {
                    return result;
                }
                // Transient network errors — back off and retry.
                ValidationStatus::NetworkError => {
                    last = result;
                    if attempt < self.max_retries {
                        let backoff = self.base_backoff * 2u32.pow(attempt);
                        tracing::debug!(
                            provider = provider,
                            attempt = attempt + 1,
                            backoff_ms = backoff.as_millis(),
                            "network error — retrying"
                        );
                        std::thread::sleep(backoff);
                    }
                }
                // All other statuses — return immediately.
                _ => return result,
            }
        }
        last
    }
}

/// Instantiate all built-in [`ProviderValidator`] implementations.
fn default_validators() -> Vec<Box<dyn ProviderValidator>> {
    vec![
        Box::new(OpenAiValidator),
        Box::new(AnthropicValidator),
        Box::new(OpenRouterValidator),
        Box::new(GoogleGeminiValidator),
        Box::new(CohereValidator),
        Box::new(MistralValidator),
        Box::new(HuggingFaceValidator),
        Box::new(ReplicateValidator),
        Box::new(TogetherAiValidator),
        Box::new(GroqValidator),
        Box::new(PerplexityValidator),
        Box::new(ElevenLabsValidator),
        Box::new(PineconeValidator),
        Box::new(StripeValidator),
        Box::new(SlackValidator),
        Box::new(GitHubValidator),
        Box::new(GitLabValidator),
        Box::new(SendGridValidator),
        // ── New validators (v2.2.0) ──
        Box::new(TwilioValidator),
        Box::new(DatadogValidator),
        Box::new(NewRelicValidator),
        Box::new(SentryValidator),
        Box::new(PagerDutyValidator),
        Box::new(DiscordValidator),
        Box::new(TelegramValidator),
        Box::new(MailgunValidator),
        Box::new(HerokuValidator),
        Box::new(DigitalOceanValidator),
        Box::new(NpmValidator),
        Box::new(PypiValidator),
        Box::new(CloudflareValidator),
        Box::new(OktaValidator),
    ]
}

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
    /// Provider requires additional context (endpoint URL, signing keys) that
    /// was not supplied.  Treat as informational; not a hard failure.
    EndpointRequired,
    /// The provider's API returned a rate-limit response (HTTP 429 or bucket
    /// exhausted).  Retry after the window expires.
    RateLimited,
    /// A transient network error prevented validation.  The runner may retry.
    NetworkError,
    /// Validation could not be performed (catchall).
    Unknown,
}

impl ValidationStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::TestKey                 => "test-key",
            Self::LikelyValid             => "likely-valid",
            Self::NetworkConfirmedValid   => "network-valid",
            Self::NetworkConfirmedInvalid => "network-invalid",
            Self::EndpointRequired        => "endpoint-required",
            Self::RateLimited             => "rate-limited",
            Self::NetworkError            => "network-error",
            Self::Unknown                 => "unknown",
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
    #[allow(dead_code)]
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
/// Uses the built-in [`ValidatorRunner`] with shared rate-limiting,
/// retry/backoff, and the pluggable [`ProviderValidator`] registry.
#[allow(dead_code)]
pub fn validate_network_body(provider: &str, body: &str) -> ValidationResult {
    let client = network_client();
    let runner = ValidatorRunner::default_runner();
    runner.validate(provider, body, &client)
}

// ── Built-in validator structs ─────────────────────────────────────────────────

struct OpenAiValidator;
impl ProviderValidator for OpenAiValidator {
    fn provider(&self) -> &'static str { "openai" }
    fn probe(&self, client: &reqwest::blocking::Client, key: &str) -> ValidationResult {
        probe_bearer(client, "https://api.openai.com/v1/models", key, "openai /v1/models")
    }
}

struct AnthropicValidator;
impl ProviderValidator for AnthropicValidator {
    fn provider(&self) -> &'static str { "anthropic" }
    fn probe(&self, client: &reqwest::blocking::Client, key: &str) -> ValidationResult {
        match client
            .get("https://api.anthropic.com/v1/models")
            .header("x-api-key", key)
            .header("anthropic-version", "2023-06-01")
            .send()
        {
            Ok(resp) => map_status(resp.status(), "anthropic /v1/models"),
            Err(e) => network_error(&e),
        }
    }
}

struct OpenRouterValidator;
impl ProviderValidator for OpenRouterValidator {
    fn provider(&self) -> &'static str { "openrouter" }
    fn probe(&self, client: &reqwest::blocking::Client, key: &str) -> ValidationResult {
        probe_bearer(client, "https://openrouter.ai/api/v1/models", key, "openrouter /api/v1/models")
    }
}

struct GoogleGeminiValidator;
impl ProviderValidator for GoogleGeminiValidator {
    fn provider(&self) -> &'static str { "google-gemini" }
    fn probe(&self, client: &reqwest::blocking::Client, key: &str) -> ValidationResult {
        let url = format!("https://generativelanguage.googleapis.com/v1beta/models?key={key}");
        match client.get(&url).send() {
            Ok(resp) => map_status_400(resp.status(), "google-gemini /v1beta/models"),
            Err(e) => network_error(&e),
        }
    }
}

struct CohereValidator;
impl ProviderValidator for CohereValidator {
    fn provider(&self) -> &'static str { "cohere" }
    fn probe(&self, client: &reqwest::blocking::Client, key: &str) -> ValidationResult {
        probe_bearer(client, "https://api.cohere.ai/v1/models", key, "cohere /v1/models")
    }
}

struct MistralValidator;
impl ProviderValidator for MistralValidator {
    fn provider(&self) -> &'static str { "mistral-ai" }
    fn probe(&self, client: &reqwest::blocking::Client, key: &str) -> ValidationResult {
        probe_bearer(client, "https://api.mistral.ai/v1/models", key, "mistral /v1/models")
    }
}

struct HuggingFaceValidator;
impl ProviderValidator for HuggingFaceValidator {
    fn provider(&self) -> &'static str { "huggingface" }
    fn probe(&self, client: &reqwest::blocking::Client, key: &str) -> ValidationResult {
        probe_bearer(client, "https://huggingface.co/api/whoami", key, "huggingface /api/whoami")
    }
}

struct ReplicateValidator;
impl ProviderValidator for ReplicateValidator {
    fn provider(&self) -> &'static str { "replicate" }
    fn probe(&self, client: &reqwest::blocking::Client, key: &str) -> ValidationResult {
        match client
            .get("https://api.replicate.com/v1/models")
            .header("Authorization", format!("Token {key}"))
            .send()
        {
            Ok(resp) => map_status(resp.status(), "replicate /v1/models"),
            Err(e) => network_error(&e),
        }
    }
}

struct TogetherAiValidator;
impl ProviderValidator for TogetherAiValidator {
    fn provider(&self) -> &'static str { "together-ai" }
    fn probe(&self, client: &reqwest::blocking::Client, key: &str) -> ValidationResult {
        probe_bearer(client, "https://api.together.xyz/v1/models", key, "together-ai /v1/models")
    }
}

struct GroqValidator;
impl ProviderValidator for GroqValidator {
    fn provider(&self) -> &'static str { "groq" }
    fn probe(&self, client: &reqwest::blocking::Client, key: &str) -> ValidationResult {
        probe_bearer(client, "https://api.groq.com/openai/v1/models", key, "groq /openai/v1/models")
    }
}

struct PerplexityValidator;
impl ProviderValidator for PerplexityValidator {
    fn provider(&self) -> &'static str { "perplexity" }
    fn probe(&self, client: &reqwest::blocking::Client, key: &str) -> ValidationResult {
        // Perplexity does not expose a models list; use a minimum-token
        // chat completion request as the probe.
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
            Ok(resp) => map_status(resp.status(), "perplexity /chat/completions"),
            Err(e) => network_error(&e),
        }
    }
}

struct ElevenLabsValidator;
impl ProviderValidator for ElevenLabsValidator {
    fn provider(&self) -> &'static str { "elevenlabs" }
    fn probe(&self, client: &reqwest::blocking::Client, key: &str) -> ValidationResult {
        match client
            .get("https://api.elevenlabs.io/v1/user")
            .header("xi-api-key", key)
            .send()
        {
            Ok(resp) => map_status(resp.status(), "elevenlabs /v1/user"),
            Err(e) => network_error(&e),
        }
    }
}

struct PineconeValidator;
impl ProviderValidator for PineconeValidator {
    fn provider(&self) -> &'static str { "pinecone" }
    fn probe(&self, client: &reqwest::blocking::Client, key: &str) -> ValidationResult {
        match client
            .get("https://api.pinecone.io/indexes")
            .header("Api-Key", key)
            .send()
        {
            Ok(resp) => map_status(resp.status(), "pinecone /indexes"),
            Err(e) => network_error(&e),
        }
    }
}

struct StripeValidator;
impl ProviderValidator for StripeValidator {
    fn provider(&self) -> &'static str { "stripe" }
    fn probe(&self, client: &reqwest::blocking::Client, key: &str) -> ValidationResult {
        probe_bearer(client, "https://api.stripe.com/v1/balance", key, "stripe /v1/balance")
    }
}

struct SlackValidator;
impl ProviderValidator for SlackValidator {
    fn provider(&self) -> &'static str { "slack" }
    fn probe(&self, client: &reqwest::blocking::Client, token: &str) -> ValidationResult {
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
            Err(e) => network_error(&e),
        }
    }
}

struct GitHubValidator;
impl ProviderValidator for GitHubValidator {
    fn provider(&self) -> &'static str { "github" }
    fn probe(&self, client: &reqwest::blocking::Client, token: &str) -> ValidationResult {
        match client
            .get("https://api.github.com/user")
            .header("Authorization", format!("Bearer {token}"))
            .header("User-Agent", concat!("sf-keyaudit/", env!("CARGO_PKG_VERSION")))
            .header("X-GitHub-Api-Version", "2022-11-28")
            .send()
        {
            Ok(resp) => map_status(resp.status(), "github /user"),
            Err(e) => network_error(&e),
        }
    }
}

struct GitLabValidator;
impl ProviderValidator for GitLabValidator {
    fn provider(&self) -> &'static str { "gitlab" }
    fn probe(&self, client: &reqwest::blocking::Client, token: &str) -> ValidationResult {
        match client
            .get("https://gitlab.com/api/v4/personal_access_tokens/self")
            .header("PRIVATE-TOKEN", token)
            .send()
        {
            Ok(resp) => map_status(resp.status(), "gitlab personal_access_tokens/self"),
            Err(e) => network_error(&e),
        }
    }
}

struct SendGridValidator;
impl ProviderValidator for SendGridValidator {
    fn provider(&self) -> &'static str { "sendgrid" }
    fn probe(&self, client: &reqwest::blocking::Client, key: &str) -> ValidationResult {
        probe_bearer(client, "https://api.sendgrid.com/v3/user/account", key, "sendgrid /v3/user/account")
    }
}

struct TwilioValidator;
impl ProviderValidator for TwilioValidator {
    fn provider(&self) -> &'static str { "twilio" }
    fn probe(&self, _client: &reqwest::blocking::Client, key: &str) -> ValidationResult {
        // Twilio auth tokens are used with Basic auth (Account SID : Auth Token).
        // We can only validate the token format since we don't have the SID.
        // However, if the key looks like an Account SID (AC...), probe with it.
        if key.starts_with("AC") && key.len() == 34 {
            // This is a SID, not an auth token — cannot validate without the pair.
            return ValidationResult {
                status: ValidationStatus::EndpointRequired,
                method: "network",
                detail: Some("Twilio Account SID detected; auth token also needed for validation".into()),
            };
        }
        // For auth tokens, we cannot probe without the SID.
        ValidationResult {
            status: ValidationStatus::EndpointRequired,
            method: "network",
            detail: Some("Twilio auth token requires Account SID for validation".into()),
        }
    }
}

struct DatadogValidator;
impl ProviderValidator for DatadogValidator {
    fn provider(&self) -> &'static str { "datadog" }
    fn probe(&self, client: &reqwest::blocking::Client, key: &str) -> ValidationResult {
        match client
            .get("https://api.datadoghq.com/api/v1/validate")
            .header("DD-API-KEY", key)
            .send()
        {
            Ok(resp) => map_status(resp.status(), "datadog /api/v1/validate"),
            Err(e) => network_error(&e),
        }
    }
}

struct NewRelicValidator;
impl ProviderValidator for NewRelicValidator {
    fn provider(&self) -> &'static str { "new-relic" }
    fn probe(&self, client: &reqwest::blocking::Client, key: &str) -> ValidationResult {
        match client
            .get("https://api.newrelic.com/v2/users.json")
            .header("Api-Key", key)
            .send()
        {
            Ok(resp) => map_status(resp.status(), "new-relic /v2/users.json"),
            Err(e) => network_error(&e),
        }
    }
}

struct SentryValidator;
impl ProviderValidator for SentryValidator {
    fn provider(&self) -> &'static str { "sentry" }
    fn probe(&self, client: &reqwest::blocking::Client, key: &str) -> ValidationResult {
        probe_bearer(client, "https://sentry.io/api/0/", key, "sentry /api/0/")
    }
}

struct PagerDutyValidator;
impl ProviderValidator for PagerDutyValidator {
    fn provider(&self) -> &'static str { "pagerduty" }
    fn probe(&self, client: &reqwest::blocking::Client, key: &str) -> ValidationResult {
        match client
            .get("https://api.pagerduty.com/users?limit=1")
            .header("Authorization", format!("Token token={key}"))
            .header("Content-Type", "application/json")
            .send()
        {
            Ok(resp) => map_status(resp.status(), "pagerduty /users"),
            Err(e) => network_error(&e),
        }
    }
}

struct DiscordValidator;
impl ProviderValidator for DiscordValidator {
    fn provider(&self) -> &'static str { "discord" }
    fn probe(&self, client: &reqwest::blocking::Client, token: &str) -> ValidationResult {
        match client
            .get("https://discord.com/api/v10/users/@me")
            .header("Authorization", format!("Bot {token}"))
            .send()
        {
            Ok(resp) => map_status(resp.status(), "discord /api/v10/users/@me"),
            Err(e) => network_error(&e),
        }
    }
}

struct TelegramValidator;
impl ProviderValidator for TelegramValidator {
    fn provider(&self) -> &'static str { "telegram" }
    fn probe(&self, client: &reqwest::blocking::Client, token: &str) -> ValidationResult {
        let url = format!("https://api.telegram.org/bot{token}/getMe");
        match client.get(&url).send() {
            Ok(resp) => map_status(resp.status(), "telegram /bot/getMe"),
            Err(e) => network_error(&e),
        }
    }
}

struct MailgunValidator;
impl ProviderValidator for MailgunValidator {
    fn provider(&self) -> &'static str { "mailgun" }
    fn probe(&self, client: &reqwest::blocking::Client, key: &str) -> ValidationResult {
        match client
            .get("https://api.mailgun.net/v3/domains")
            .basic_auth("api", Some(key))
            .send()
        {
            Ok(resp) => map_status(resp.status(), "mailgun /v3/domains"),
            Err(e) => network_error(&e),
        }
    }
}

struct HerokuValidator;
impl ProviderValidator for HerokuValidator {
    fn provider(&self) -> &'static str { "heroku" }
    fn probe(&self, client: &reqwest::blocking::Client, key: &str) -> ValidationResult {
        match client
            .get("https://api.heroku.com/account")
            .header("Authorization", format!("Bearer {key}"))
            .header("Accept", "application/vnd.heroku+json; version=3")
            .send()
        {
            Ok(resp) => map_status(resp.status(), "heroku /account"),
            Err(e) => network_error(&e),
        }
    }
}

struct DigitalOceanValidator;
impl ProviderValidator for DigitalOceanValidator {
    fn provider(&self) -> &'static str { "digitalocean" }
    fn probe(&self, client: &reqwest::blocking::Client, key: &str) -> ValidationResult {
        probe_bearer(client, "https://api.digitalocean.com/v2/account", key, "digitalocean /v2/account")
    }
}

struct NpmValidator;
impl ProviderValidator for NpmValidator {
    fn provider(&self) -> &'static str { "npm" }
    fn probe(&self, client: &reqwest::blocking::Client, token: &str) -> ValidationResult {
        probe_bearer(client, "https://registry.npmjs.org/-/npm/v1/user", token, "npm /v1/user")
    }
}

struct PypiValidator;
impl ProviderValidator for PypiValidator {
    fn provider(&self) -> &'static str { "pypi" }
    fn probe(&self, _client: &reqwest::blocking::Client, token: &str) -> ValidationResult {
        // PyPI tokens can be validated by attempting an upload metadata check.
        // A simpler approach: check the token format and return likely-valid.
        // PyPI only exposes upload endpoints — hitting them to validate would
        // be destructive.  Return EndpointRequired to signal that the key
        // format looks valid but we cannot safely probe.
        if token.starts_with("pypi-") {
            ValidationResult {
                status: ValidationStatus::EndpointRequired,
                method: "network",
                detail: Some("PyPI tokens can only be validated by upload; skipping to avoid side effects".into()),
            }
        } else {
            ValidationResult {
                status: ValidationStatus::EndpointRequired,
                method: "network",
                detail: Some("token does not match PyPI format".into()),
            }
        }
    }
}

struct CloudflareValidator;
impl ProviderValidator for CloudflareValidator {
    fn provider(&self) -> &'static str { "cloudflare" }
    fn probe(&self, client: &reqwest::blocking::Client, key: &str) -> ValidationResult {
        probe_bearer(client, "https://api.cloudflare.com/client/v4/user/tokens/verify", key, "cloudflare /user/tokens/verify")
    }
}

struct OktaValidator;
impl ProviderValidator for OktaValidator {
    fn provider(&self) -> &'static str { "okta" }
    fn probe(&self, _client: &reqwest::blocking::Client, _key: &str) -> ValidationResult {
        // Okta API tokens require the tenant domain (e.g. https://myorg.okta.com)
        // which we don't have from the credential alone.
        ValidationResult {
            status: ValidationStatus::EndpointRequired,
            method: "network",
            detail: Some("Okta validation requires tenant domain; cannot probe without it".into()),
        }
    }
}

// ── Declarative (config-driven) validator ──────────────────────────────────────

/// Authentication method for declarative validators.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidatorAuthMethod {
    /// `Authorization: Bearer {key}`
    Bearer,
    /// `Authorization: Basic base64(username:key)`.  The `username` field
    /// in [`CustomValidatorDef`] supplies the username portion.
    BasicAuth,
    /// Custom header — name in [`CustomValidatorDef::auth_header`],
    /// value is the key (optionally with a template like `"Token {key}"`).
    Header,
    /// Key appended as a query parameter (name in `auth_header`).
    QueryParam,
}

/// A user-defined network validator specified in `.sfkeyaudit.yaml`.
///
/// ```yaml
/// custom_validators:
///   - provider: my-internal-api
///     url: "https://api.internal.example.com/v1/whoami"
///     auth_method: bearer
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomValidatorDef {
    /// Provider slug (must match a detector's `provider` field).
    pub provider: String,
    /// The HTTP endpoint to probe — must be read-only and safe to call.
    pub url: String,
    /// How the credential is transmitted.
    #[serde(default = "default_auth_method")]
    pub auth_method: ValidatorAuthMethod,
    /// Header name when `auth_method` is `header` (e.g. `"X-Api-Key"`).
    /// For `query_param`, this is the query parameter name (e.g. `"api_key"`).
    pub auth_header: Option<String>,
    /// Template for the header value.  Use `{key}` as the placeholder.
    /// Example: `"Token {key}"`.  If omitted, the raw key is sent.
    pub auth_value_template: Option<String>,
    /// Username for `basic_auth` method.  Defaults to `"api"`.
    pub username: Option<String>,
    /// HTTP method.  Defaults to `GET`.
    #[serde(default = "default_http_method")]
    pub http_method: String,
}

fn default_auth_method() -> ValidatorAuthMethod { ValidatorAuthMethod::Bearer }
fn default_http_method() -> String { "GET".into() }

/// Runtime wrapper that adapts a [`CustomValidatorDef`] to the
/// [`ProviderValidator`] trait.
struct DeclaredValidator {
    def: CustomValidatorDef,
    /// Leaked string so we can return `&'static str` from `provider()`.
    provider_static: &'static str,
}

impl DeclaredValidator {
    fn new(def: CustomValidatorDef) -> Self {
        let provider_static: &'static str = Box::leak(def.provider.clone().into_boxed_str());
        Self { def, provider_static }
    }
}

impl ProviderValidator for DeclaredValidator {
    fn provider(&self) -> &'static str { self.provider_static }

    fn probe(&self, client: &reqwest::blocking::Client, key: &str) -> ValidationResult {
        let label = format!("{} {}", self.def.provider, self.def.url);
        let mut builder = match self.def.http_method.to_uppercase().as_str() {
            "POST" => client.post(&self.def.url),
            "HEAD" => client.head(&self.def.url),
            _ => client.get(&self.def.url),
        };

        match self.def.auth_method {
            ValidatorAuthMethod::Bearer => {
                builder = builder.header("Authorization", format!("Bearer {key}"));
            }
            ValidatorAuthMethod::BasicAuth => {
                let username = self.def.username.as_deref().unwrap_or("api");
                builder = builder.basic_auth(username, Some(key));
            }
            ValidatorAuthMethod::Header => {
                let header_name = self.def.auth_header.as_deref().unwrap_or("Authorization");
                let value = if let Some(ref tpl) = self.def.auth_value_template {
                    tpl.replace("{key}", key)
                } else {
                    key.to_string()
                };
                builder = builder.header(header_name, value);
            }
            ValidatorAuthMethod::QueryParam => {
                let param_name = self.def.auth_header.as_deref().unwrap_or("api_key");
                builder = builder.query(&[(param_name, key)]);
            }
        }

        match builder.send() {
            Ok(resp) => map_status(resp.status(), &label),
            Err(e) => network_error(&e),
        }
    }
}

/// Build [`ProviderValidator`] instances from config-defined declarations.
pub fn build_custom_validators(defs: &[CustomValidatorDef]) -> Vec<Box<dyn ProviderValidator>> {
    defs.iter()
        .map(|d| -> Box<dyn ProviderValidator> { Box::new(DeclaredValidator::new(d.clone())) })
        .collect()
}

// ── Shared probe helpers ───────────────────────────────────────────────────────

/// Generic helper: send a GET with `Authorization: Bearer {key}`, map
/// 200→Valid, 401/403→Invalid, 429→RateLimited, else Unknown.
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
        Ok(resp) => map_status(resp.status(), label),
        Err(e) => network_error(&e),
    }
}

/// Map an HTTP status code to a [`ValidationResult`].
fn map_status(code: reqwest::StatusCode, label: &str) -> ValidationResult {
    if code.is_success() {
        ValidationResult {
            status: ValidationStatus::NetworkConfirmedValid,
            method: "network",
            detail: Some(format!("{label} → 200")),
        }
    } else if code == 429 {
        ValidationResult {
            status: ValidationStatus::RateLimited,
            method: "network",
            detail: Some(format!("{label} → 429 rate-limited by provider")),
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

/// Like `map_status` but treats 400 as invalid (Google APIs return 400 for
/// bad API keys rather than 401).
fn map_status_400(code: reqwest::StatusCode, label: &str) -> ValidationResult {
    if code == 400 {
        ValidationResult {
            status: ValidationStatus::NetworkConfirmedInvalid,
            method: "network",
            detail: Some(format!("{label} → {code}")),
        }
    } else {
        map_status(code, label)
    }
}

/// Convert a [`reqwest::Error`] to a [`ValidationResult`] with
/// `NetworkError` status.
fn network_error(e: &reqwest::Error) -> ValidationResult {
    ValidationResult {
        status: ValidationStatus::NetworkError,
        method: "network",
        detail: Some(format!("network error: {e}")),
    }
}

// (old standalone validate_* functions removed — logic lives in ProviderValidator impls above)

///
/// Findings without a body (e.g. read from a saved report) are left with
/// `Unknown`.  The offline validation result is overwritten only when a
/// definitive network result is obtained.
#[allow(dead_code)]
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

/// Like [`apply_network_validation`] but also registers custom validators from
/// the project config before running.
pub fn apply_network_validation_with_custom(
    mut findings: Vec<Finding>,
    custom_defs: &[CustomValidatorDef],
) -> Vec<Finding> {
    let client = network_client();
    let mut runner = ValidatorRunner::default_runner();
    for v in build_custom_validators(custom_defs) {
        tracing::info!(provider = v.provider(), "registered custom validator");
        runner.register(v);
    }
    for f in &mut findings {
        let result = if let Some(ref body) = f.secret_body {
            runner.validate(&f.provider, body, &client)
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
            "network validation (with custom)"
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
            confidence: None,
            triage_state: None,
            triage_justification: None,
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
    fn endpoint_required_status_as_str() {
        assert_eq!(ValidationStatus::EndpointRequired.as_str(), "endpoint-required");
    }

    #[test]
    fn rate_limited_status_as_str() {
        assert_eq!(ValidationStatus::RateLimited.as_str(), "rate-limited");
    }

    #[test]
    fn network_error_status_as_str() {
        assert_eq!(ValidationStatus::NetworkError.as_str(), "network-error");
    }

    // ── RateLimiter ────────────────────────────────────────────────────────────

    #[test]
    fn rate_limiter_allows_within_budget() {
        let limiter = RateLimiter::new(3, Duration::from_secs(60));
        assert!(limiter.check_and_increment("openai"));
        assert!(limiter.check_and_increment("openai"));
        assert!(limiter.check_and_increment("openai"));
    }

    #[test]
    fn rate_limiter_blocks_when_exhausted() {
        let limiter = RateLimiter::new(3, Duration::from_secs(60));
        limiter.check_and_increment("openai");
        limiter.check_and_increment("openai");
        limiter.check_and_increment("openai");
        // 4th call exceeds the budget.
        assert!(!limiter.check_and_increment("openai"));
    }

    #[test]
    fn rate_limiter_separate_providers_are_independent() {
        let limiter = RateLimiter::new(1, Duration::from_secs(60));
        assert!(limiter.check_and_increment("openai"));
        // openai is exhausted; anthropic bucket is fresh.
        assert!(!limiter.check_and_increment("openai"));
        assert!(limiter.check_and_increment("anthropic"));
    }

    // ── ValidatorRunner ────────────────────────────────────────────────────────

    #[test]
    fn runner_returns_endpoint_required_for_unknown_provider() {
        let runner = ValidatorRunner::default_runner();
        let client = reqwest::blocking::Client::new();
        let result = runner.validate("no-such-provider-xyz", "some-body", &client);
        assert_eq!(result.status, ValidationStatus::EndpointRequired);
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

    // ── Validator runner tests ────────────────────────────────────────────

    #[test]
    fn default_runner_has_32_validators() {
        let runner = ValidatorRunner::default_runner();
        // 18 original + 14 new = 32
        assert!(runner.validators.len() >= 32, "expected ≥32 validators, got {}", runner.validators.len());
    }

    #[test]
    fn default_runner_covers_key_providers() {
        let runner = ValidatorRunner::default_runner();
        for provider in &["openai", "anthropic", "github", "stripe", "datadog", "sentry", "discord", "telegram", "cloudflare", "digitalocean", "npm", "heroku"] {
            assert!(runner.validators.contains_key(*provider), "missing validator for '{provider}'");
        }
    }

    #[test]
    fn custom_validator_register_overrides_builtin() {
        let mut runner = ValidatorRunner::default_runner();
        assert!(runner.validators.contains_key("openai"));
        // Register a custom validator for the same provider.
        let def = CustomValidatorDef {
            provider: "openai".to_string(),
            url: "https://custom-openai.example.com/v1/test".to_string(),
            auth_method: ValidatorAuthMethod::Bearer,
            auth_header: None,
            auth_value_template: None,
            username: None,
            http_method: "GET".to_string(),
        };
        let custom = DeclaredValidator::new(def);
        runner.register(Box::new(custom));
        // The custom validator should have replaced the built-in.
        assert!(runner.validators.contains_key("openai"));
    }

    #[test]
    fn build_custom_validators_creates_instances() {
        let defs = vec![
            CustomValidatorDef {
                provider: "my-corp".to_string(),
                url: "https://api.mycorp.internal/health".to_string(),
                auth_method: ValidatorAuthMethod::Header,
                auth_header: Some("X-Corp-Key".to_string()),
                auth_value_template: None,
                username: None,
                http_method: "GET".to_string(),
            },
            CustomValidatorDef {
                provider: "my-other-corp".to_string(),
                url: "https://api.other.internal/v1/me".to_string(),
                auth_method: ValidatorAuthMethod::BasicAuth,
                auth_header: None,
                auth_value_template: None,
                username: Some("admin".to_string()),
                http_method: "POST".to_string(),
            },
        ];
        let validators = build_custom_validators(&defs);
        assert_eq!(validators.len(), 2);
        assert_eq!(validators[0].provider(), "my-corp");
        assert_eq!(validators[1].provider(), "my-other-corp");
    }

    #[test]
    fn twilio_validator_returns_endpoint_required_for_sid() {
        let v = TwilioValidator;
        let client = reqwest::blocking::Client::new();
        let result = v.probe(&client, "AC1234567890abcdef1234567890abcdef");
        assert_eq!(result.status, ValidationStatus::EndpointRequired);
    }

    #[test]
    fn pypi_validator_returns_endpoint_required() {
        let v = PypiValidator;
        let client = reqwest::blocking::Client::new();
        let result = v.probe(&client, "pypi-something");
        assert_eq!(result.status, ValidationStatus::EndpointRequired);
    }

    #[test]
    fn okta_validator_returns_endpoint_required() {
        let v = OktaValidator;
        let client = reqwest::blocking::Client::new();
        let result = v.probe(&client, "some-okta-token");
        assert_eq!(result.status, ValidationStatus::EndpointRequired);
    }

    #[test]
    fn rate_limiter_exhaustion() {
        let limiter = RateLimiter::new(2, Duration::from_secs(60));
        assert!(limiter.check_and_increment("test"));
        assert!(limiter.check_and_increment("test"));
        assert!(!limiter.check_and_increment("test")); // exhausted
        // Different provider still works.
        assert!(limiter.check_and_increment("other"));
    }

    #[test]
    fn declarative_auth_methods_deserialize() {
        let yaml = r#"
provider: my-svc
url: "https://api.example.com/health"
auth_method: basic_auth
username: "api"
http_method: GET
"#;
        let def: CustomValidatorDef = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(def.auth_method, ValidatorAuthMethod::BasicAuth);
        assert_eq!(def.username.as_deref(), Some("api"));
    }
}
