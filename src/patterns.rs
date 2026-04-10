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

use crate::config::CustomRuleDef;
use crate::entropy::HIGH_CONFIDENCE_THRESHOLD;
use crate::error::AuditError;
use fancy_regex::Regex;

/// Detector confidence tier.
///
/// Every built-in pattern is assigned one of three tiers that reflect how
/// reliably the regex alone (before entropy filtering) identifies a real
/// credential versus a false positive.
///
/// | Tier | Description |
/// |------|-------------|
/// | `High` | Structured prefix + fixed-length body.  FP rate is very low. |
/// | `Medium` | Context-sensitive match (env-var name + value).  Low-to-medium FP rate. |
/// | `Low` | Heuristic or highly generic patterns.  Higher FP rate; treat as informational. |
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ConfidenceTier {
    High,
    Medium,
    Low,
}

impl ConfidenceTier {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::High   => "high",
            Self::Medium => "medium",
            Self::Low    => "low",
        }
    }

    /// Numeric rank for ordering: High = 2, Medium = 1, Low = 0.
    fn rank(self) -> u8 {
        match self {
            Self::High   => 2,
            Self::Medium => 1,
            Self::Low    => 0,
        }
    }
}

impl PartialOrd for ConfidenceTier {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ConfidenceTier {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.rank().cmp(&other.rank())
    }
}

impl std::fmt::Display for ConfidenceTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl std::str::FromStr for ConfidenceTier {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "high"   => Ok(Self::High),
            "medium" => Ok(Self::Medium),
            "low"    => Ok(Self::Low),
            other => Err(format!(
                "unknown confidence tier '{other}'; valid values: high, medium, low"
            )),
        }
    }
}

/// A compiled pattern entry.
pub struct Pattern {
    /// Stable identifier, e.g. `openai-project-key-v2`.
    pub id: String,
    /// Provider slug used in Finding.provider, e.g. `openai`.
    pub provider: String,
    /// Human-readable one-line description.
    #[allow(dead_code)]
    pub description: String,
    /// Compiled regex.  Must contain a named group `body`.
    /// May optionally contain a named group `prefix`.
    pub regex: Regex,
    /// Minimum Shannon entropy (bits/char) for the `body` capture group for
    /// the finding to be classified as high-confidence (exit 1).
    /// Matches below this threshold go into `low_confidence_findings`.
    pub min_entropy: f64,
    /// Severity: "critical", "high", or "medium".
    pub severity: String,
    /// Provider-specific remediation guidance.
    pub remediation: String,
    /// Detector confidence tier: how reliably the pattern identifies a real
    /// credential before entropy filtering.
    pub confidence: ConfidenceTier,
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
    severity: &'static str,
    remediation: &'static str,
    /// Detector confidence tier for this pattern.
    confidence: ConfidenceTier,
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
            severity: "critical",
            remediation: "Revoke at https://console.anthropic.com/settings/keys and regenerate immediately. Replace with an environment variable or secrets manager.",
            confidence: ConfidenceTier::High,
        },
        // ── OpenAI ─────────────────────────────────────────────────────────
        PatternDef {
            id: "openai-project-key-v2",
            provider: "openai",
            description: "OpenAI project API key (sk-proj- prefix)",
            pattern: r"(?P<prefix>sk-proj-)(?P<body>[A-Za-z0-9_-]{100,200})",
            min_entropy: 4.0,
            severity: "critical",
            remediation: "Revoke at https://platform.openai.com/api-keys. Rotate all dependent services and store in a secrets manager.",
            confidence: ConfidenceTier::High,
        },
        PatternDef {
            id: "openai-svcacct-key-v1",
            provider: "openai",
            description: "OpenAI service-account API key (sk-svcacct- prefix)",
            pattern: r"(?P<prefix>sk-svcacct-)(?P<body>[A-Za-z0-9_-]{100,200})",
            min_entropy: 4.0,
            severity: "critical",
            remediation: "Revoke at https://platform.openai.com/api-keys. Rotate all dependent services and store in a secrets manager.",
            confidence: ConfidenceTier::High,
        },
        // ── OpenRouter ─────────────────────────────────────────────────────
        PatternDef {
            id: "openrouter-api-key-v1",
            provider: "openrouter",
            description: "OpenRouter API key (sk-or- prefix)",
            pattern: r"(?P<prefix>sk-or-(?:v\d+-?)?)(?P<body>[A-Za-z0-9_-]{40,100})",
            min_entropy: 3.5,
            severity: "high",
            remediation: "Revoke at https://openrouter.ai/keys and regenerate.",
            confidence: ConfidenceTier::High,
        },
        // ── OpenAI legacy / Stability AI ───────────────────────────────────
        PatternDef {
            id: "openai-legacy-key-v1",
            provider: "openai",
            description: "OpenAI legacy API key (bare sk- prefix, 48 alphanumeric chars)",
            pattern: r"(?P<prefix>sk-)(?!proj-|svcacct-|ant-|or-)(?P<body>[A-Za-z0-9]{48})(?:[^A-Za-z0-9]|$)",
            min_entropy: 3.5,
            severity: "critical",
            remediation: "Revoke at https://platform.openai.com/api-keys. Rotate all dependent services and store in a secrets manager.",
            confidence: ConfidenceTier::High,
        },
        // ── Stability AI (context-sensitive) ───────────────────────────────
        PatternDef {
            id: "stability-ai-key-v1",
            provider: "stability-ai",
            description: "Stability AI API key (STABILITY_API_KEY context)",
            pattern: r#"(?i)(?:STABILITY(?:_AI)?_API_KEY)[\s]*[=:]["']?\s*(?P<body>sk-[A-Za-z0-9]{48})"#,
            min_entropy: 3.5,
            severity: "high",
            remediation: "Revoke at https://platform.stability.ai/account/keys and regenerate.",
            confidence: ConfidenceTier::Medium,
        },
        // ── Google AI / Gemini ─────────────────────────────────────────────
        PatternDef {
            id: "google-gemini-key-v1",
            provider: "google-gemini",
            description: "Google AI / Gemini API key (AIza prefix, 39 chars total)",
            pattern: r"(?P<prefix>AIza)(?P<body>[0-9A-Za-z_-]{35})",
            min_entropy: 3.5,
            severity: "critical",
            remediation: "Revoke at https://console.cloud.google.com/apis/credentials. Restrict key to required APIs only and move to a secrets manager.",
            confidence: ConfidenceTier::High,
        },
        // ── Google Vertex AI Service Account ───────────────────────────────
        PatternDef {
            id: "google-vertex-service-account-v1",
            provider: "google-vertex-ai",
            description: "Google Vertex AI service account JSON (type:service_account with private_key_id)",
            pattern: r#"(?s)"type"\s*:\s*"service_account".{0,1000}?"private_key_id"\s*:\s*"(?P<body>[^"]{20,64})""#,
            min_entropy: 3.0,
            severity: "critical",
            remediation: "Delete and regenerate the service account key at https://console.cloud.google.com/iam-admin/serviceaccounts. Prefer Workload Identity Federation over long-lived service account keys.",
            confidence: ConfidenceTier::Medium,
        },
        // ── AWS ────────────────────────────────────────────────────────────
        PatternDef {
            id: "aws-access-key-id-v1",
            provider: "aws-bedrock",
            description: "AWS access key ID (AKIA/ASIA prefix)",
            pattern: r"(?P<prefix>(?:AKIA|ASIA))(?P<body>[0-9A-Z]{16})",
            min_entropy: 3.0,
            severity: "critical",
            remediation: "Deactivate in AWS IAM console at https://console.aws.amazon.com/iam/. Use IAM roles and instance profiles instead of long-lived access keys.",
            confidence: ConfidenceTier::High,
        },
        // AWS Secret Access Key always travels alongside an Access Key ID.
        // Context-sensitive: requires AWS_SECRET_ACCESS_KEY variable name.
        PatternDef {
            id: "aws-secret-access-key-v1",
            provider: "aws",
            description: "AWS secret access key (AWS_SECRET_ACCESS_KEY env var, 40-char base64 body)",
            pattern: r#"(?i)(?:AWS_SECRET_ACCESS_KEY|aws_secret_key)[\s]*[=:]["']?\s*(?P<body>[A-Za-z0-9+/]{40})"#,
            min_entropy: 4.0,
            severity: "critical",
            remediation: "Deactivate in AWS IAM console, remove from the codebase, and rotate all dependent services immediately. Use IAM roles instead of long-lived static credentials.",
            confidence: ConfidenceTier::Medium,
        },
        // ── Azure OpenAI ───────────────────────────────────────────────────
        PatternDef {
            id: "azure-openai-subscription-key-v1",
            provider: "azure-openai",
            description: "Azure OpenAI / Cognitive Services subscription key (Ocp-Apim-Subscription-Key header)",
            pattern: r#"(?i)(?P<prefix>Ocp-Apim-Subscription-Key[\s]*[:=]["']?\s*)(?P<body>[0-9a-fA-F]{32})"#,
            min_entropy: 3.0,
            severity: "critical",
            remediation: "Regenerate at Azure Portal → Cognitive Services → Keys. Use Managed Identity instead of subscription keys where possible.",
            confidence: ConfidenceTier::Medium,
        },
        // Azure service principal client secret (context-sensitive).
        PatternDef {
            id: "azure-service-principal-secret-v1",
            provider: "azure",
            description: "Azure service principal client secret (AZURE_CLIENT_SECRET env var)",
            pattern: r#"(?i)AZURE_CLIENT_SECRET[\s]*[=:]["']?\s*(?P<body>[A-Za-z0-9~._\-]{34,40})"#,
            min_entropy: 3.5,
            severity: "critical",
            remediation: "Rotate the client secret at Azure Portal → Entra ID → App registrations → Certificates & secrets. Use managed identity where possible.",
            confidence: ConfidenceTier::Medium,
        },
        // ── GCP OAuth client secret ────────────────────────────────────────
        PatternDef {
            id: "gcp-oauth-client-secret-v1",
            provider: "gcp",
            description: "GCP OAuth 2.0 client secret (GOCSPX- prefix)",
            pattern: r"(?P<prefix>GOCSPX-)(?P<body>[A-Za-z0-9_-]{28})",
            min_entropy: 3.5,
            severity: "high",
            remediation: "Revoke at https://console.cloud.google.com/apis/credentials and create a new OAuth client credential.",
            confidence: ConfidenceTier::High,
        },
        // ── Cohere ─────────────────────────────────────────────────────────
        PatternDef {
            id: "cohere-api-key-v1",
            provider: "cohere",
            description: "Cohere API key (co- prefix)",
            pattern: r"(?P<prefix>co-)(?P<body>[A-Za-z0-9]{40,80})",
            min_entropy: 3.5,
            severity: "high",
            remediation: "Revoke at https://dashboard.cohere.com/api-keys and regenerate.",
            confidence: ConfidenceTier::High,
        },
        // ── Mistral AI ─────────────────────────────────────────────────────
        PatternDef {
            id: "mistral-api-key-v1",
            provider: "mistral-ai",
            description: "Mistral AI API key (mi- prefix with hex body)",
            pattern: r"(?P<prefix>mi-)(?P<body>[A-Za-z0-9]{40,80})",
            min_entropy: 3.5,
            severity: "high",
            remediation: "Revoke at https://console.mistral.ai/api-keys and regenerate.",
            confidence: ConfidenceTier::High,
        },
        // ── Hugging Face ───────────────────────────────────────────────────
        PatternDef {
            id: "huggingface-token-v1",
            provider: "huggingface",
            description: "Hugging Face user access token (hf_ prefix)",
            pattern: r"(?P<prefix>hf_)(?P<body>[A-Za-z0-9]{34,50})",
            min_entropy: 3.5,
            severity: "high",
            remediation: "Revoke at https://huggingface.co/settings/tokens and regenerate.",
            confidence: ConfidenceTier::High,
        },
        // ── Replicate ──────────────────────────────────────────────────────
        PatternDef {
            id: "replicate-api-token-v1",
            provider: "replicate",
            description: "Replicate API token (r8_ prefix, 40-char hex body)",
            pattern: r"(?P<prefix>r8_)(?P<body>[a-fA-F0-9]{40})",
            min_entropy: 3.5,
            severity: "high",
            remediation: "Revoke at https://replicate.com/account/api-tokens and regenerate.",
            confidence: ConfidenceTier::High,
        },
        // ── Together AI ────────────────────────────────────────────────────
        PatternDef {
            id: "together-ai-key-v1",
            provider: "together-ai",
            description: "Together AI API key (context-sensitive: TOGETHER variable with 40-char hex body)",
            pattern: r#"(?i)(?:TOGETHER(?:_AI)?_API_KEY)[\s]*[=:]["']?\s*(?P<body>[a-fA-F0-9]{40,64})"#,
            min_entropy: 3.5,
            severity: "high",
            remediation: "Revoke at https://api.together.xyz/settings/api-keys and regenerate.",
            confidence: ConfidenceTier::Medium,
        },
        // ── Groq ───────────────────────────────────────────────────────────
        PatternDef {
            id: "groq-api-key-v1",
            provider: "groq",
            description: "Groq API key (gsk_ prefix)",
            pattern: r"(?P<prefix>gsk_(?:live_|test_)?)(?P<body>[A-Za-z0-9]{52})",
            min_entropy: 3.5,
            severity: "high",
            remediation: "Revoke at https://console.groq.com/keys and regenerate.",
            confidence: ConfidenceTier::High,
        },
        // ── Perplexity AI ──────────────────────────────────────────────────
        PatternDef {
            id: "perplexity-key-v1",
            provider: "perplexity",
            description: "Perplexity AI API key (pplx- prefix)",
            pattern: r"(?P<prefix>pplx-)(?P<body>[A-Za-z0-9]{48})",
            min_entropy: 3.5,
            severity: "high",
            remediation: "Revoke at https://www.perplexity.ai/account/api and regenerate.",
            confidence: ConfidenceTier::High,
        },
        // ── ElevenLabs ─────────────────────────────────────────────────────
        PatternDef {
            id: "elevenlabs-api-key-v1",
            provider: "elevenlabs",
            description: "ElevenLabs API key (xi-api-key header or ELEVENLABS_API_KEY env var)",
            pattern: r#"(?i)(?P<prefix>(?:xi-api-key|ELEVENLABS_API_KEY|XI_API_KEY)[\s]*[:=]["']?\s*)(?P<body>[a-fA-F0-9]{32})"#,
            min_entropy: 3.0,
            severity: "medium",
            remediation: "Revoke at https://elevenlabs.io/app/api-key and regenerate.",
            confidence: ConfidenceTier::Medium,
        },
        // ── Pinecone ───────────────────────────────────────────────────────
        PatternDef {
            id: "pinecone-api-key-v1",
            provider: "pinecone",
            description: "Pinecone API key (UUID-format, context-sensitive: PINECONE variable)",
            pattern: r#"(?i)(?:PINECONE_API_KEY|PINECONE_KEY)[\s]*[=:]["']?\s*(?P<body>[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})"#,
            min_entropy: 3.0,
            severity: "medium",
            remediation: "Revoke at https://app.pinecone.io/ and regenerate.",
            confidence: ConfidenceTier::Medium,
        },
        // ── Weaviate ───────────────────────────────────────────────────────
        PatternDef {
            id: "weaviate-api-key-v1",
            provider: "weaviate",
            description: "Weaviate API key (X-Weaviate-Api-Key header or WEAVIATE_API_KEY env var)",
            pattern: r#"(?i)(?P<prefix>(?:X-Weaviate-Api-Key|WEAVIATE_API_KEY)[\s]*[:=]["']?\s*)(?P<body>[A-Za-z0-9+/=_-]{20,100})"#,
            min_entropy: 3.0,
            severity: "medium",
            remediation: "Revoke and regenerate at https://console.weaviate.cloud/.",
            confidence: ConfidenceTier::Medium,
        },
        // ── GitHub App private key ─────────────────────────────────────────
        // GitHub App RSA private keys begin with a PEM header.
        PatternDef {
            id: "github-app-private-key-v1",
            provider: "github",
            description: "GitHub App RSA private key (PEM BEGIN RSA PRIVATE KEY header)",
            pattern: r"(?P<body>-----BEGIN RSA PRIVATE KEY-----[A-Za-z0-9+/=\r\n]{100,}-----END RSA PRIVATE KEY-----)",
            min_entropy: 4.5,
            severity: "critical",
            remediation: "Delete the private key file, revoke the GitHub App key at https://github.com/settings/apps, generate a new key, and store it in a secrets manager or environment variable.",
            confidence: ConfidenceTier::High,
        },
        // ── npm ─────────────────────────────────────────────────────────────
        PatternDef {
            id: "npm-access-token-v1",
            provider: "npm",
            description: "npm access token (npm_XXXX prefix, 36-char base64url body)",
            pattern: r"(?P<prefix>npm_)(?P<body>[A-Za-z0-9]{36})",
            min_entropy: 3.5,
            severity: "high",
            remediation: "Revoke at https://www.npmjs.com/settings/<user>/tokens and regenerate with the minimum required scope.",
            confidence: ConfidenceTier::High,
        },
        // ── PyPI ────────────────────────────────────────────────────────────
        PatternDef {
            id: "pypi-api-token-v1",
            provider: "pypi",
            description: "PyPI API token (pypi- prefix, 36+ char opaque body)",
            pattern: r"(?P<prefix>pypi-)(?P<body>[A-Za-z0-9_\-]{36,128})",
            min_entropy: 3.5,
            severity: "high",
            remediation: "Revoke at https://pypi.org/manage/account/token/ and regenerate with package-scoped permissions.",
            confidence: ConfidenceTier::High,
        },
        // ── Docker Hub ──────────────────────────────────────────────────────
        PatternDef {
            id: "docker-hub-pat-v1",
            provider: "docker-hub",
            description: "Docker Hub personal access token (dckr_pat_ prefix)",
            pattern: r"(?P<prefix>dckr_pat_)(?P<body>[A-Za-z0-9_\-]{26,40})",
            min_entropy: 3.5,
            severity: "high",
            remediation: "Revoke at https://hub.docker.com/settings/security and create a new token with minimal required scopes.",
            confidence: ConfidenceTier::High,
        },
        // ── Slack webhook ──────────────────────────────────────────────────
        PatternDef {
            id: "slack-webhook-url-v1",
            provider: "slack",
            description: "Slack incoming webhook URL (hooks.slack.com path with service token)",
            pattern: r"(?P<body>https://hooks\.slack\.com/services/T[A-Z0-9]{8,10}/B[A-Z0-9]{8,10}/[A-Za-z0-9]{24})",
            min_entropy: 3.5,
            severity: "high",
            remediation: "Revoke at https://api.slack.com/apps → Incoming Webhooks → Revoke URL and generate a new webhook.",
            confidence: ConfidenceTier::High,
        },
        // ── MongoDB connection URI ──────────────────────────────────────────
        PatternDef {
            id: "mongodb-conn-string-v1",
            provider: "mongodb",
            description: "MongoDB Atlas connection string (mongodb+srv:// URI with credentials)",
            pattern: r"(?P<body>mongodb(?:\+srv)?://[^:@\s]{1,64}:[^@\s]{8,128}@[A-Za-z0-9._-]+(?::[0-9]+)?(?:/[^\s?#]*)?(?:\?[^\s#]*)?)",
            min_entropy: 3.0,
            severity: "critical",
            remediation: "Rotate the database user password immediately via MongoDB Atlas or your self-hosted cluster admin. Never commit connection strings; use a secrets manager.",
            confidence: ConfidenceTier::High,
        },
        // ── PostgreSQL connection URI ───────────────────────────────────────
        PatternDef {
            id: "postgres-conn-string-v1",
            provider: "postgres",
            description: "PostgreSQL connection URI with embedded credentials",
            pattern: r"(?P<body>postgres(?:ql)?://[^:@\s]{1,64}:[^@\s]{8,128}@[A-Za-z0-9._-]+(?::[0-9]+)?/[^\s?#]+)",
            min_entropy: 3.0,
            severity: "critical",
            remediation: "Rotate the database user password and remove the connection string from source code. Use a secrets manager or Vault-injected environment variable.",
            confidence: ConfidenceTier::High,
        },
        // ── Redis URL with password ─────────────────────────────────────────
        PatternDef {
            id: "redis-url-with-password-v1",
            provider: "redis",
            description: "Redis connection URL with embedded password (redis://:password@...)",
            pattern: r"(?P<body>rediss?://(?:[^:@\s]*:)?(?P<key>[^@\s]{8,}@)[A-Za-z0-9._-]+(?::[0-9]+)?(?:/[0-9]*)?)",
            min_entropy: 3.0,
            severity: "high",
            remediation: "Rotate the Redis password with CONFIG SET requirepass, update all clients, and store the URL in a secrets manager.",
            confidence: ConfidenceTier::High,
        },
        // ── JWT secret ─────────────────────────────────────────────────────
        // Context-sensitive: requires a JWT_SECRET / JWT_SIGNING_KEY variable name.
        PatternDef {
            id: "jwt-secret-v1",
            provider: "jwt",
            description: "JWT signing secret or key (JWT_SECRET / JWT_SIGNING_KEY env var)",
            pattern: r#"(?i)(?:JWT_SECRET(?:_KEY)?|JWT_SIGNING_KEY|JWT_KEY)[\s]*[=:]["']?\s*(?P<body>[A-Za-z0-9+/=_\-]{32,256})"#,
            min_entropy: 4.0,
            severity: "critical",
            remediation: "Rotate the JWT signing secret, invalidate all existing tokens, and store the new secret in a secrets manager.",
            confidence: ConfidenceTier::Medium,
        },
        // ── SSH private keys ────────────────────────────────────────────────
        PatternDef {
            id: "ssh-private-key-v1",
            provider: "ssh",
            description: "SSH OpenSSH or legacy private key block (various PRIVATE KEY header types)",
            pattern: r"(?P<body>-----BEGIN (?:OPENSSH |EC |DSA |)PRIVATE KEY-----[A-Za-z0-9+/=\r\n]{64,}-----END (?:OPENSSH |EC |DSA |)PRIVATE KEY-----)",
            min_entropy: 4.5,
            severity: "critical",
            remediation: "Remove the private key file, rotate the key pair (ssh-keygen), update all authorized_keys entries, and store the private key in a secrets manager or ssh-agent.",
            confidence: ConfidenceTier::High,
        },
        // ── PEM private key (generic) ───────────────────────────────────────
        // Catches arbitrary PEM-wrapped private keys not matched above.
        PatternDef {
            id: "pem-private-key-generic-v1",
            provider: "pem",
            description: "PEM-encoded private key block (generic PRIVATE KEY header)",
            pattern: r"(?P<body>-----BEGIN PRIVATE KEY-----[A-Za-z0-9+/=\r\n]{64,}-----END PRIVATE KEY-----)",
            min_entropy: 4.5,
            severity: "critical",
            remediation: "Remove the private key from source control, rotate the associated certificate or key pair, and store the key in a hardware security module or secrets manager.",
            confidence: ConfidenceTier::High,
        },
        // ── Stripe ─────────────────────────────────────────────────────────
        PatternDef {
            id: "stripe-live-secret-key-v1",
            provider: "stripe",
            description: "Stripe live secret API key (sk_live_ prefix)",
            pattern: r"(?P<prefix>sk_live_)(?P<body>[0-9a-zA-Z]{24,96})",
            min_entropy: 3.5,
            severity: "critical",
            remediation: "Revoke immediately at https://dashboard.stripe.com/apikeys. Live keys can charge real payment methods.",
            confidence: ConfidenceTier::High,
        },
        PatternDef {
            id: "stripe-restricted-key-v1",
            provider: "stripe",
            description: "Stripe restricted secret key (rk_live_ prefix)",
            pattern: r"(?P<prefix>rk_live_)(?P<body>[0-9a-zA-Z]{24,96})",
            min_entropy: 3.5,
            severity: "high",
            remediation: "Revoke at https://dashboard.stripe.com/apikeys and regenerate with minimal required permissions.",
            confidence: ConfidenceTier::High,
        },
        // ── Slack tokens ───────────────────────────────────────────────────
        PatternDef {
            id: "slack-bot-token-v1",
            provider: "slack",
            description: "Slack bot OAuth token (xoxb- prefix)",
            pattern: r"(?P<prefix>xoxb-)(?P<body>[0-9]{10,13}-[0-9]{10,13}-[0-9A-Za-z]{24,28})",
            min_entropy: 3.5,
            severity: "high",
            remediation: "Revoke at https://api.slack.com/apps → OAuth & Permissions → Revoke Token.",
            confidence: ConfidenceTier::High,
        },
        PatternDef {
            id: "slack-user-token-v1",
            provider: "slack",
            description: "Slack user OAuth token (xoxp- prefix)",
            pattern: r"(?P<prefix>xoxp-)(?P<body>[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[0-9a-f]{32})",
            min_entropy: 3.5,
            severity: "high",
            remediation: "Revoke at https://api.slack.com/apps → OAuth & Permissions → Revoke Token.",
            confidence: ConfidenceTier::High,
        },
        // ── GitHub tokens ──────────────────────────────────────────────────
        PatternDef {
            id: "github-fine-grained-pat-v1",
            provider: "github",
            description: "GitHub fine-grained personal access token (github_pat_ prefix, 82-char body)",
            pattern: r"(?P<prefix>github_pat_)(?P<body>[A-Za-z0-9_]{82})",
            min_entropy: 4.0,
            severity: "critical",
            remediation: "Revoke at https://github.com/settings/tokens and regenerate. Apply least-privilege repository scopes.",
            confidence: ConfidenceTier::High,
        },
        PatternDef {
            id: "github-classic-pat-v1",
            provider: "github",
            description: "GitHub classic personal access token (ghp_ prefix)",
            pattern: r"(?P<prefix>ghp_)(?P<body>[A-Za-z0-9]{36})",
            min_entropy: 3.5,
            severity: "critical",
            remediation: "Revoke at https://github.com/settings/tokens and regenerate. Migrate to fine-grained tokens with minimal scopes.",
            confidence: ConfidenceTier::High,
        },
        PatternDef {
            id: "github-oauth-token-v1",
            provider: "github",
            description: "GitHub OAuth access token (gho_ prefix)",
            pattern: r"(?P<prefix>gho_)(?P<body>[A-Za-z0-9]{36})",
            min_entropy: 3.5,
            severity: "high",
            remediation: "Revoke the OAuth token via the issuing app's settings or https://github.com/settings/applications.",
            confidence: ConfidenceTier::High,
        },
        // ── GitLab ─────────────────────────────────────────────────────────
        PatternDef {
            id: "gitlab-pat-v1",
            provider: "gitlab",
            description: "GitLab personal access token (glpat- prefix)",
            pattern: r"(?P<prefix>glpat-)(?P<body>[0-9A-Za-z_\-]{20})",
            min_entropy: 3.5,
            severity: "critical",
            remediation: "Revoke at https://gitlab.com/-/profile/personal_access_tokens and regenerate with minimal scopes.",
            confidence: ConfidenceTier::High,
        },
        // ── SendGrid ───────────────────────────────────────────────────────
        PatternDef {
            id: "sendgrid-api-key-v1",
            provider: "sendgrid",
            description: "SendGrid API key (SG. prefix, two base64url segments)",
            pattern: r"(?P<prefix>SG\.)(?P<body>[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})",
            min_entropy: 4.0,
            severity: "high",
            remediation: "Revoke at https://app.sendgrid.com/settings/api_keys and regenerate with minimal required permissions.",
            confidence: ConfidenceTier::High,
        },
        // ── Twilio ─────────────────────────────────────────────────────────
        PatternDef {
            id: "twilio-account-sid-v1",
            provider: "twilio",
            description: "Twilio Account SID in context (AC prefix, 32 hex chars)",
            pattern: r#"(?i)(?:TWILIO_ACCOUNT_SID|ACCOUNT_SID)[\s]*[=:]["']?\s*(?P<body>AC[a-f0-9]{32})"#,
            min_entropy: 3.0,
            severity: "high",
            remediation: "Rotate API credentials at https://console.twilio.com/ and update all dependent integrations.",
            confidence: ConfidenceTier::Medium,
        },
        PatternDef {
            id: "twilio-auth-token-v1",
            provider: "twilio",
            description: "Twilio Auth Token in context (TWILIO_AUTH_TOKEN env var)",
            pattern: r#"(?i)(?:TWILIO_AUTH_TOKEN|TWILIO_TOKEN)[\s]*[=:]["']?\s*(?P<body>[a-f0-9]{32})"#,
            min_entropy: 3.0,
            severity: "critical",
            remediation: "Rotate the Auth Token at https://console.twilio.com/ and invalidate all existing sessions.",
            confidence: ConfidenceTier::Medium,
        },
        // ── HashiCorp Vault ────────────────────────────────────────────────
        PatternDef {
            id: "vault-service-token-v1",
            provider: "hashicorp-vault",
            description: "HashiCorp Vault service token (hvs. prefix, base64url body)",
            pattern: r"(?P<prefix>hvs\.)(?P<body>[A-Za-z0-9_-]{24,100})",
            min_entropy: 4.0,
            severity: "critical",
            remediation: "Revoke the token immediately via `vault token revoke <token>` or the Vault UI. Audit the lease log for any unauthorized access, then regenerate using the least-privilege policy.",
            confidence: ConfidenceTier::High,
        },
        PatternDef {
            id: "vault-batch-token-v1",
            provider: "hashicorp-vault",
            description: "HashiCorp Vault batch token (hvb. prefix)",
            pattern: r"(?P<prefix>hvb\.)(?P<body>[A-Za-z0-9_-]{100,300})",
            min_entropy: 4.0,
            severity: "high",
            remediation: "Batch tokens expire automatically but source them from VAULT_TOKEN env var. Remove any hard-coded batch tokens from configuration files.",
            confidence: ConfidenceTier::High,
        },
        PatternDef {
            id: "vault-root-token-v1",
            provider: "hashicorp-vault",
            description: "HashiCorp Vault root token (hvr. prefix or s. legacy prefix) in variable context",
            pattern: r#"(?i)(?:VAULT_TOKEN|VAULT_ROOT_TOKEN)[\s]*[=:]["']?\s*(?P<body>(?:hvr\.|s\.)[A-Za-z0-9_-]{20,100})"#,
            min_entropy: 4.0,
            severity: "critical",
            remediation: "Root tokens must be revoked immediately. Generate a short-lived root token only when required for initial setup, then revoke it. Use AppRole or K8s auth for programmatic access.",
            confidence: ConfidenceTier::Medium,
        },
        // ── Cloudflare ────────────────────────────────────────────────────
        PatternDef {
            id: "cloudflare-api-token-v1",
            provider: "cloudflare",
            description: "Cloudflare API token (40-char alphanumeric) in variable context",
            pattern: r#"(?i)(?:CLOUDFLARE_API_TOKEN|CF_API_TOKEN|cloudflare_token)[\s]*[=:]["']?\s*(?P<body>[A-Za-z0-9_-]{40})"#,
            min_entropy: 4.0,
            severity: "critical",
            remediation: "Revoke at https://dash.cloudflare.com/profile/api-tokens and create a new token with the minimum required permissions (scoped to zone or account).",
            confidence: ConfidenceTier::Medium,
        },
        PatternDef {
            id: "cloudflare-global-api-key-v1",
            provider: "cloudflare",
            description: "Cloudflare Global API key (legacy, 37-char hex) in variable context",
            pattern: r#"(?i)(?:CLOUDFLARE_API_KEY|CF_API_KEY|cloudflare_key)[\s]*[=:]["']?\s*(?P<body>[a-f0-9]{37})"#,
            min_entropy: 3.5,
            severity: "critical",
            remediation: "Rotate the Global API key at https://dash.cloudflare.com/profile/api-tokens. Prefer scoped API tokens over the unrestricted Global key.",
            confidence: ConfidenceTier::Medium,
        },
        // ── Datadog ───────────────────────────────────────────────────────
        PatternDef {
            id: "datadog-api-key-v1",
            provider: "datadog",
            description: "Datadog API key (32-char hex) in variable context",
            pattern: r#"(?i)(?:DD_API_KEY|DATADOG_API_KEY|datadog_key)[\s]*[=:]["']?\s*(?P<body>[a-f0-9]{32})"#,
            min_entropy: 3.5,
            severity: "high",
            remediation: "Revoke at https://app.datadoghq.com/organization-settings/api-keys and generate a new key. Scope keys to specific ingest pipelines.",
            confidence: ConfidenceTier::Medium,
        },
        PatternDef {
            id: "datadog-app-key-v1",
            provider: "datadog",
            description: "Datadog application key (40-char hex) in variable context",
            pattern: r#"(?i)(?:DD_APP_KEY|DATADOG_APP_KEY|datadog_app_key)[\s]*[=:]["']?\s*(?P<body>[a-f0-9]{40})"#,
            min_entropy: 3.5,
            severity: "high",
            remediation: "Revoke at https://app.datadoghq.com/organization-settings/application-keys and regenerate with minimal permissions.",
            confidence: ConfidenceTier::Medium,
        },
        // ── Terraform Cloud ───────────────────────────────────────────────
        PatternDef {
            id: "terraform-cloud-token-v1",
            provider: "terraform-cloud",
            description: "Terraform Cloud / Terraform Enterprise API token (tf- or atlas- prefix)",
            pattern: r"(?P<prefix>(?:tf-|atlas-))(?P<body>[A-Za-z0-9_\-.]{14,})",
            min_entropy: 4.0,
            severity: "critical",
            remediation: "Revoke at https://app.terraform.io/app/settings/tokens and create a new token. Use workload identity federation instead of static tokens for CI/CD pipelines.",
            confidence: ConfidenceTier::High,
        },
        PatternDef {
            id: "terraform-cloud-env-token-v1",
            provider: "terraform-cloud",
            description: "Terraform Cloud API token in environment variable context (TFC_TOKEN or ATLAS_TOKEN)",
            pattern: r#"(?i)(?:ATLAS_TOKEN|TFC_TOKEN|TFE_TOKEN|TERRAFORM_TOKEN)[\s]*[=:]["']?\s*(?P<body>[A-Za-z0-9_\-.]{14,})"#,
            min_entropy: 4.0,
            severity: "critical",
            remediation: "Revoke at https://app.terraform.io/app/settings/tokens and rotate. Use workload identity federation for CI/CD pipelines.",
            confidence: ConfidenceTier::Medium,
        },

        // ── Source Control ────────────────────────────────────────────────
        PatternDef {
            id: "github-actions-token-v1",
            provider: "github",
            description: "GitHub Actions temporary token (ghs_ prefix)",
            pattern: r"(?P<prefix>ghs_)(?P<body>[A-Za-z0-9]{36})",
            min_entropy: 3.5,
            severity: "high",
            remediation: "GitHub Actions tokens expire after the workflow run. Ensure this value is not persisted in logs or artifacts.",
            confidence: ConfidenceTier::High,
        },
        PatternDef {
            id: "github-refresh-token-v1",
            provider: "github",
            description: "GitHub OAuth refresh token (ghr_ prefix)",
            pattern: r"(?P<prefix>ghr_)(?P<body>[A-Za-z0-9]{76})",
            min_entropy: 3.5,
            severity: "critical",
            remediation: "Revoke the OAuth application authorization at https://github.com/settings/applications.",
            confidence: ConfidenceTier::High,
        },
        PatternDef {
            id: "gitlab-runner-token-v1",
            provider: "gitlab",
            description: "GitLab CI runner registration or authentication token",
            pattern: r"(?P<prefix>glrt-)(?P<body>[A-Za-z0-9_-]{20})",
            min_entropy: 3.5,
            severity: "high",
            remediation: "Rotate at GitLab → CI/CD Settings → Runners. A leaked runner token allows arbitrary CI job registration.",
            confidence: ConfidenceTier::High,
        },
        PatternDef {
            id: "bitbucket-app-password-v1",
            provider: "bitbucket",
            description: "Bitbucket app password in URL or environment variable context",
            pattern: r#"(?i)(?:BITBUCKET_APP_PASSWORD|BB_APP_PASSWORD)[\s]*[=:]["']?\s*(?P<body>[A-Za-z0-9+/]{20,})"#,
            min_entropy: 3.5,
            severity: "critical",
            remediation: "Revoke at https://bitbucket.org/account/settings/app-passwords and regenerate with minimum required permissions.",
            confidence: ConfidenceTier::Medium,
        },

        // ── Package Registries ────────────────────────────────────────────
        PatternDef {
            id: "rubygems-api-key-v1",
            provider: "rubygems",
            description: "RubyGems API key (rubygems_ prefix)",
            pattern: r"(?P<prefix>rubygems_)(?P<body>[a-f0-9]{48})",
            min_entropy: 3.5,
            severity: "critical",
            remediation: "Revoke at https://rubygems.org/profile/api_keys and regenerate.",
            confidence: ConfidenceTier::High,
        },

        // ── Communication & Messaging ─────────────────────────────────────
        PatternDef {
            id: "discord-bot-token-v1",
            provider: "discord",
            description: "Discord bot token",
            pattern: r"(?P<body>[A-Za-z0-9_-]{24}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,38})",
            min_entropy: 4.5,
            severity: "critical",
            remediation: "Reset at https://discord.com/developers/applications → Bot → Reset Token. Regenerate immediately if exposed.",
            confidence: ConfidenceTier::High,
        },
        PatternDef {
            id: "telegram-bot-token-v1",
            provider: "telegram",
            description: "Telegram bot API token (numeric ID : alphanumeric)",
            pattern: r"(?P<body>[0-9]{8,12}:[A-Za-z0-9_-]{35})",
            min_entropy: 3.5,
            severity: "high",
            remediation: "Revoke via BotFather /revoke command and generate a replacement token.",
            confidence: ConfidenceTier::High,
        },
        PatternDef {
            id: "mailgun-api-key-v1",
            provider: "mailgun",
            description: "Mailgun API key (key- prefix)",
            pattern: r"(?P<prefix>key-)(?P<body>[a-f0-9]{32})",
            min_entropy: 3.5,
            severity: "critical",
            remediation: "Revoke at https://app.mailgun.com/settings/api_security and regenerate.",
            confidence: ConfidenceTier::High,
        },

        // ── Payment Processors ────────────────────────────────────────────
        PatternDef {
            id: "stripe-secret-key-v1",
            provider: "stripe",
            description: "Stripe secret API key (sk_live_ prefix)",
            pattern: r"(?P<prefix>sk_live_)(?P<body>[A-Za-z0-9]{24,99})",
            min_entropy: 3.5,
            severity: "critical",
            remediation: "Revoke at https://dashboard.stripe.com/apikeys and regenerate. Never commit live keys; use sk_test_ for development.",
            confidence: ConfidenceTier::High,
        },
        PatternDef {
            id: "paypal-braintree-token-v1",
            provider: "braintree",
            description: "Braintree access token (access_token$ prefix)",
            pattern: r"(?P<prefix>access_token\$production\$)(?P<body>[a-z0-9]{16}\$[a-f0-9]{32})",
            min_entropy: 3.5,
            severity: "critical",
            remediation: "Revoke at https://www.braintreegateway.com/login → API Keys and regenerate.",
            confidence: ConfidenceTier::High,
        },

        // ── Cloud Providers ───────────────────────────────────────────────
        PatternDef {
            id: "digitalocean-pat-v1",
            provider: "digitalocean",
            description: "DigitalOcean personal access token (dop_v1_ prefix)",
            pattern: r"(?P<prefix>dop_v1_)(?P<body>[a-f0-9]{64})",
            min_entropy: 3.5,
            severity: "critical",
            remediation: "Revoke at https://cloud.digitalocean.com/account/api/tokens and regenerate.",
            confidence: ConfidenceTier::High,
        },
        PatternDef {
            id: "digitalocean-oauth-token-v1",
            provider: "digitalocean",
            description: "DigitalOcean OAuth token (doo_v1_ prefix)",
            pattern: r"(?P<prefix>doo_v1_)(?P<body>[a-f0-9]{64})",
            min_entropy: 3.5,
            severity: "critical",
            remediation: "Revoke at https://cloud.digitalocean.com/account/api/tokens and regenerate.",
            confidence: ConfidenceTier::High,
        },
        PatternDef {
            id: "linode-api-token-v1",
            provider: "linode",
            description: "Linode / Akamai Cloud personal access token in environment variable context",
            pattern: r#"(?i)(?:LINODE_TOKEN|LINODE_API_KEY|LINODE_API_TOKEN)[\s]*[=:]["']?\s*(?P<body>[a-f0-9]{64})"#,
            min_entropy: 3.5,
            severity: "critical",
            remediation: "Revoke at https://cloud.linode.com/profile/tokens and regenerate.",
            confidence: ConfidenceTier::Medium,
        },

        // ── Observability & Monitoring ────────────────────────────────────
        PatternDef {
            id: "new-relic-license-key-v1",
            provider: "new-relic",
            description: "New Relic license key (NRAK- prefix)",
            pattern: r"(?P<prefix>NRAK-)(?P<body>[A-Z0-9]{27})",
            min_entropy: 3.0,
            severity: "critical",
            remediation: "Revoke at https://one.newrelic.com/admin-portal/api-keys and regenerate.",
            confidence: ConfidenceTier::High,
        },
        PatternDef {
            id: "new-relic-user-api-key-v1",
            provider: "new-relic",
            description: "New Relic user API key (NRUA- prefix)",
            pattern: r"(?P<prefix>NRUA-)(?P<body>[A-Za-z0-9_-]{27})",
            min_entropy: 3.0,
            severity: "critical",
            remediation: "Revoke at https://one.newrelic.com/admin-portal/api-keys and regenerate.",
            confidence: ConfidenceTier::High,
        },
        PatternDef {
            id: "sentry-dsn-v1",
            provider: "sentry",
            description: "Sentry DSN or auth token in environment variable context",
            pattern: r#"(?i)(?:SENTRY_DSN|SENTRY_AUTH_TOKEN)[\s]*[=:]["']?\s*(?P<body>[A-Za-z0-9:/._-]{30,})"#,
            min_entropy: 3.5,
            severity: "high",
            remediation: "Rotate at https://sentry.io/settings/ → Auth Tokens. For DSNs, rotate the project's SDK key.",
            confidence: ConfidenceTier::Medium,
        },
        PatternDef {
            id: "splunk-hec-token-v1",
            provider: "splunk",
            description: "Splunk HTTP Event Collector (HEC) token in environment variable context",
            pattern: r#"(?i)(?:SPLUNK_TOKEN|SPLUNK_HEC_TOKEN|splunk_hec_key)[\s]*[=:]["']?\s*(?P<body>[A-Za-z0-9-]{36})"#,
            min_entropy: 3.5,
            severity: "critical",
            remediation: "Revoke at Splunk → Settings → Data Inputs → HTTP Event Collector and regenerate.",
            confidence: ConfidenceTier::Medium,
        },

        // ── Authentication / Identity ─────────────────────────────────────
        PatternDef {
            id: "auth0-client-secret-v1",
            provider: "auth0",
            description: "Auth0 client secret in environment variable context",
            pattern: r#"(?i)(?:AUTH0_CLIENT_SECRET|AUTH0_SECRET)[\s]*[=:]["']?\s*(?P<body>[A-Za-z0-9_-]{32,})"#,
            min_entropy: 4.0,
            severity: "critical",
            remediation: "Rotate at Auth0 → Applications → <app> → Settings → Rotate Secret. Update all consumers immediately.",
            confidence: ConfidenceTier::Medium,
        },
        PatternDef {
            id: "okta-api-token-v1",
            provider: "okta",
            description: "Okta API token in environment variable context (00 prefix with alphanumeric body is typical)",
            pattern: r#"(?i)(?:OKTA_API_TOKEN|OKTA_TOKEN)[\s]*[=:]["']?\s*(?P<body>00[A-Za-z0-9_-]{40})"#,
            min_entropy: 3.5,
            severity: "critical",
            remediation: "Revoke at Okta Admin Console → Security → API → Tokens and regenerate with minimum required scopes.",
            confidence: ConfidenceTier::Medium,
        },
        PatternDef {
            id: "firebase-server-key-v1",
            provider: "firebase",
            description: "Firebase server key (AAAA prefix, long body)",
            pattern: r"(?P<prefix>AAAA)(?P<body>[A-Za-z0-9_-]{140,})",
            min_entropy: 4.0,
            severity: "critical",
            remediation: "Migrate to Firebase App Check and rotate at https://console.firebase.google.com/ → Project settings → Cloud Messaging.",
            confidence: ConfidenceTier::High,
        },

        // ── Database Connection Strings ───────────────────────────────────
        PatternDef {
            id: "postgres-connection-url-v1",
            provider: "postgres",
            description: "PostgreSQL connection URL with embedded credentials",
            pattern: r#"(?P<prefix>postgres(?:ql)?://)(?P<body>[^:@\s]+:[^@\s]+@[^\s/'"]{4,})"#,
            min_entropy: 3.0,
            severity: "critical",
            remediation: "Rotate the database user password. Use a secrets manager (AWS Secrets Manager, HashiCorp Vault) to inject credentials at runtime.",
            confidence: ConfidenceTier::High,
        },
        PatternDef {
            id: "mysql-connection-url-v1",
            provider: "mysql",
            description: "MySQL / MariaDB connection URL with embedded credentials",
            pattern: r#"(?P<prefix>mysql(?:2)?://)(?P<body>[^:@\s]+:[^@\s]+@[^\s/'"]{4,})"#,
            min_entropy: 3.0,
            severity: "critical",
            remediation: "Rotate the database user password and move credentials to a secrets manager.",
            confidence: ConfidenceTier::High,
        },
        PatternDef {
            id: "mongodb-connection-url-v1",
            provider: "mongodb",
            description: "MongoDB connection URL with embedded credentials",
            pattern: r#"(?P<prefix>mongodb(?:\+srv)?://)(?P<body>[^:@\s]+:[^@\s]+@[^\s/'"]{4,})"#,
            min_entropy: 3.0,
            severity: "critical",
            remediation: "Rotate the MongoDB user password at Atlas → Database Access or mongosh and store credentials in a secrets manager.",
            confidence: ConfidenceTier::High,
        },
        PatternDef {
            id: "redis-connection-url-v1",
            provider: "redis",
            description: "Redis / Valkey connection URL with embedded password",
            pattern: r#"(?P<prefix>redis(?:s)?://)(?::)?(?P<body>[^@\s/]{8,}@[^\s/'"]{4,})"#,
            min_entropy: 3.0,
            severity: "critical",
            remediation: "Rotate via CONFIG SET requirepass in redis-cli or via your cloud provider and update all consumers.",
            confidence: ConfidenceTier::High,
        },
        PatternDef {
            id: "mssql-connection-string-v1",
            provider: "mssql",
            description: "MSSQL / SQL Server connection string with Password= credential",
            pattern: r#"(?i)(?:Password|PWD)\s*=\s*(?P<body>[^;'"]{8,})"#,
            min_entropy: 3.0,
            severity: "critical",
            remediation: "Rotate the SQL Server login password and use Windows Authentication or Azure Managed Identity instead of embedded credentials.",
            confidence: ConfidenceTier::Medium,
        },

        // ── Cryptographic Material ────────────────────────────────────────
        PatternDef {
            id: "rsa-private-key-v1",
            provider: "pki",
            description: "RSA PEM private key header",
            pattern: r"(?P<body>-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----)",
            min_entropy: 1.5,
            severity: "critical",
            remediation: "Revoke and regenerate the key pair. Audit all systems that may have had access. Never commit private keys to version control.",
            confidence: ConfidenceTier::High,
        },
        PatternDef {
            id: "pgp-private-key-v1",
            provider: "pki",
            description: "PGP/GPG private key block header",
            pattern: r"(?P<body>-----BEGIN PGP PRIVATE KEY BLOCK-----)",
            min_entropy: 1.5,
            severity: "critical",
            remediation: "Revoke the key via your key server or identity provider and generate a new key pair.",
            confidence: ConfidenceTier::High,
        },
        PatternDef {
            id: "ssh-ed25519-private-key-v1",
            provider: "pki",
            description: "OpenSSH Ed25519 or ECDSA private key (BEGIN OPENSSH PRIVATE KEY)",
            pattern: r"(?P<body>-----BEGIN OPENSSH PRIVATE KEY-----)",
            min_entropy: 1.5,
            severity: "critical",
            remediation: "Remove the key from all authorized_keys files, revoke access, and generate a replacement key pair.",
            confidence: ConfidenceTier::High,
        },
        PatternDef {
            id: "jwt-secret-context-v1",
            provider: "jwt",
            description: "JWT signing secret in environment variable context",
            pattern: r#"(?i)(?:JWT_SECRET|JWT_SIGNING_KEY|JWT_PRIVATE_KEY)[\s]*[=:]["']?\s*(?P<body>[A-Za-z0-9+/=_-]{16,})"#,
            min_entropy: 4.0,
            severity: "critical",
            remediation: "Rotate the JWT signing secret and invalidate all outstanding tokens. Use asymmetric keys (RS256, ES256) in production instead of shared secrets.",
            confidence: ConfidenceTier::Medium,
        },

        // ── CI/CD & DevOps Tokens ─────────────────────────────────────────
        PatternDef {
            id: "circleci-api-token-v1",
            provider: "circleci",
            description: "CircleCI personal API token in environment variable context",
            pattern: r#"(?i)(?:CIRCLECI_TOKEN|CIRCLE_TOKEN|CIRCLECI_API_KEY)[\s]*[=:]["']?\s*(?P<body>[a-f0-9]{40})"#,
            min_entropy: 3.5,
            severity: "critical",
            remediation: "Revoke at https://app.circleci.com/settings/user/tokens and regenerate.",
            confidence: ConfidenceTier::Medium,
        },
        PatternDef {
            id: "travis-ci-api-token-v1",
            provider: "travisci",
            description: "Travis CI API token in environment variable context",
            pattern: r#"(?i)(?:TRAVIS_TOKEN|TRAVIS_API_TOKEN)[\s]*[=:]["']?\s*(?P<body>[A-Za-z0-9_-]{22})"#,
            min_entropy: 3.5,
            severity: "critical",
            remediation: "Revoke at https://travis-ci.com/account/preferences and regenerate.",
            confidence: ConfidenceTier::Medium,
        },
        PatternDef {
            id: "jenkins-api-token-v1",
            provider: "jenkins",
            description: "Jenkins API token in environment variable context",
            pattern: r#"(?i)(?:JENKINS_TOKEN|JENKINS_API_TOKEN)[\s]*[=:]["']?\s*(?P<body>[a-f0-9]{32})"#,
            min_entropy: 3.5,
            severity: "critical",
            remediation: "Revoke at Jenkins → User → Configure → API Token and regenerate.",
            confidence: ConfidenceTier::Medium,
        },
        PatternDef {
            id: "azure-devops-pat-v1",
            provider: "azure-devops",
            description: "Azure DevOps personal access token in environment variable context",
            pattern: r#"(?i)(?:AZURE_DEVOPS_TOKEN|AZDO_PAT|AZURE_DEVOPS_PAT)[\s]*[=:]["']?\s*(?P<body>[A-Za-z0-9]{52})"#,
            min_entropy: 3.5,
            severity: "critical",
            remediation: "Revoke at https://dev.azure.com/<org>/_usersSettings/tokens and regenerate with minimum required scopes.",
            confidence: ConfidenceTier::Medium,
        },

        // ── Additional Cloud & SaaS ───────────────────────────────────────
        PatternDef {
            id: "heroku-api-key-v1",
            provider: "heroku",
            description: "Heroku API key (UUID format) in environment variable context",
            pattern: r#"(?i)(?:HEROKU_API_KEY|heroku_api_token)[\s]*[=:]["']?\s*(?P<body>[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})"#,
            min_entropy: 3.5,
            severity: "critical",
            remediation: "Revoke at https://dashboard.heroku.com/account and regenerate the API key.",
            confidence: ConfidenceTier::Medium,
        },
        PatternDef {
            id: "shopify-private-app-token-v1",
            provider: "shopify",
            description: "Shopify private app access token (shppa_ prefix)",
            pattern: r"(?P<prefix>shppa_)(?P<body>[A-Fa-f0-9]{32})",
            min_entropy: 3.5,
            severity: "critical",
            remediation: "Revoke at Shopify Admin → Apps → Manage private apps and regenerate.",
            confidence: ConfidenceTier::High,
        },
        PatternDef {
            id: "shopify-custom-app-token-v1",
            provider: "shopify",
            description: "Shopify custom app access token (shpat_ prefix)",
            pattern: r"(?P<prefix>shpat_)(?P<body>[A-Fa-f0-9]{32})",
            min_entropy: 3.5,
            severity: "critical",
            remediation: "Revoke at Shopify Admin → Apps and regenerate the custom app token.",
            confidence: ConfidenceTier::High,
        },
        PatternDef {
            id: "pagerduty-api-key-v1",
            provider: "pagerduty",
            description: "PagerDuty API key in environment variable context",
            pattern: r#"(?i)(?:PAGERDUTY_TOKEN|PAGERDUTY_API_KEY|PD_TOKEN)[\s]*[=:]["']?\s*(?P<body>[A-Za-z0-9_\-+]{20,})"#,
            min_entropy: 3.5,
            severity: "critical",
            remediation: "Revoke at https://app.pagerduty.com/api_keys and regenerate.",
            confidence: ConfidenceTier::Medium,
        },
        PatternDef {
            id: "jira-api-token-v1",
            provider: "jira",
            description: "Atlassian Jira / Confluence API token in environment variable context",
            pattern: r#"(?i)(?:JIRA_API_TOKEN|ATLASSIAN_TOKEN|CONFLUENCE_TOKEN)[\s]*[=:]["']?\s*(?P<body>[A-Za-z0-9_+/=]{24,})"#,
            min_entropy: 3.5,
            severity: "critical",
            remediation: "Revoke at https://id.atlassian.com/manage-profile/security/api-tokens and regenerate.",
            confidence: ConfidenceTier::Medium,
        },

        // ── Blockchain / Web3 ─────────────────────────────────────────────
        PatternDef {
            id: "ethereum-private-key-v1",
            provider: "ethereum",
            description: "Ethereum / EVM raw private key (0x-prefixed 256-bit hex)",
            pattern: r"(?P<prefix>0x)(?P<body>[a-fA-F0-9]{64})(?:[^a-fA-F0-9]|$)",
            min_entropy: 3.5,
            severity: "critical",
            remediation: "This private key controls on-chain funds. Transfer assets immediately to a new wallet and never reuse this key.",
            confidence: ConfidenceTier::Medium,
        },
        PatternDef {
            id: "infura-api-key-v1",
            provider: "infura",
            description: "Infura project (API) key in environment variable context",
            pattern: r#"(?i)(?:INFURA_KEY|INFURA_PROJECT_ID|INFURA_API_KEY)[\s]*[=:]["']?\s*(?P<body>[a-f0-9]{32})"#,
            min_entropy: 3.5,
            severity: "high",
            remediation: "Regenerate at https://app.infura.io/ and restrict key usage to required networks.",
            confidence: ConfidenceTier::Medium,
        },
    ];

    defs.iter()
        .map(|def| {
            let regex = Regex::new(def.pattern).map_err(|source| AuditError::PatternCompile {
                id: def.id.to_string(),
                source,
            })?;
            Ok(Pattern {
                id: def.id.to_string(),
                provider: def.provider.to_string(),
                description: def.description.to_string(),
                regex,
                min_entropy: def.min_entropy,
                severity: def.severity.to_string(),
                remediation: def.remediation.to_string(),
                confidence: def.confidence,
            })
        })
        .collect()
}

/// Build additional [`Pattern`]s from custom rule definitions loaded from the
/// project configuration file (`.sfkeyaudit.yaml`).
pub fn build_custom_patterns(defs: &[CustomRuleDef]) -> Result<Vec<Pattern>, AuditError> {
    defs.iter()
        .map(|def| {
            let regex = Regex::new(&def.pattern).map_err(|source| AuditError::PatternCompile {
                id: def.id.clone(),
                source,
            })?;
            Ok(Pattern {
                id: def.id.clone(),
                provider: def.provider.clone(),
                description: def.description.clone().unwrap_or_default(),
                regex,
                min_entropy: def.min_entropy.unwrap_or(HIGH_CONFIDENCE_THRESHOLD),
                severity: def.severity.clone().unwrap_or_else(|| "high".to_string()),
                remediation: def.remediation.clone().unwrap_or_else(|| {
                    format!("Revoke and rotate the {} credential.", def.provider)
                }),
                // Custom rules default to Medium confidence; operators can override via severity.
                confidence: ConfidenceTier::Medium,
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
        patterns.iter().map(|p| p.provider.as_str()).collect();

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
        assert!(p.unwrap().len() >= 92, "expected at least 92 patterns");
    }

    #[test]
    fn all_patterns_have_confidence() {
        let p = patterns();
        for pat in &p {
            // Ensures every pattern has a valid confidence tier (enum exhaustiveness).
            let _ = pat.confidence.as_str();
        }
    }

    #[test]
    fn pattern_ids_are_unique() {
        let p = patterns();
        let mut ids: Vec<&str> = p.iter().map(|x| x.id.as_str()).collect();
        ids.sort_unstable();
        let before = ids.len();
        ids.dedup();
        assert_eq!(before, ids.len(), "duplicate pattern ids detected");
    }

    #[test]
    fn all_patterns_have_severity() {
        let p = patterns();
        for pat in &p {
            assert!(
                ["critical", "high", "medium"].contains(&pat.severity.as_str()),
                "pattern {} has invalid severity '{}'", pat.id, pat.severity
            );
        }
    }

    #[test]
    fn all_patterns_have_remediation() {
        let p = patterns();
        for pat in &p {
            assert!(!pat.remediation.is_empty(), "pattern {} has empty remediation", pat.id);
        }
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

    #[test]
    fn anthropic_severity_is_critical() {
        let p = patterns();
        let pat = p.iter().find(|x| x.id == "anthropic-api-key-v1").unwrap();
        assert_eq!(pat.severity, "critical");
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

    #[test]
    fn openrouter_severity_is_high() {
        let p = patterns();
        let pat = p.iter().find(|x| x.id == "openrouter-api-key-v1").unwrap();
        assert_eq!(pat.severity, "high");
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

    #[test]
    fn aws_severity_is_critical() {
        let p = patterns();
        let pat = p.iter().find(|x| x.id == "aws-access-key-id-v1").unwrap();
        assert_eq!(pat.severity, "critical");
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

    #[test]
    fn cohere_severity_is_high() {
        let p = patterns();
        let pat = p.iter().find(|x| x.id == "cohere-api-key-v1").unwrap();
        assert_eq!(pat.severity, "high");
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

    #[test]
    fn elevenlabs_severity_is_medium() {
        let p = patterns();
        let pat = p.iter().find(|x| x.id == "elevenlabs-api-key-v1").unwrap();
        assert_eq!(pat.severity, "medium");
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

    // ── build_custom_patterns ───────────────────────────────────────────────

    #[test]
    fn custom_pattern_compiles_and_has_fields() {
        let defs = vec![CustomRuleDef {
            id: "my-token-v1".to_string(),
            provider: "myco".to_string(),
            description: Some("Internal token".to_string()),
            pattern: r"myco_[A-Za-z0-9]{32}".to_string(),
            min_entropy: Some(3.0),
            severity: Some("high".to_string()),
            remediation: Some("Rotate via internal portal".to_string()),
        }];
        let built = build_custom_patterns(&defs).unwrap();
        assert_eq!(built.len(), 1);
        assert_eq!(built[0].id, "my-token-v1");
        assert_eq!(built[0].provider, "myco");
        assert_eq!(built[0].severity, "high");
    }

    #[test]
    fn custom_pattern_defaults_applied() {
        let defs = vec![CustomRuleDef {
            id: "bare-v1".to_string(),
            provider: "barecomp".to_string(),
            description: None,
            pattern: r"bare_[A-Za-z0-9]{16}".to_string(),
            min_entropy: None,
            severity: None,
            remediation: None,
        }];
        let built = build_custom_patterns(&defs).unwrap();
        assert_eq!(built[0].min_entropy, HIGH_CONFIDENCE_THRESHOLD);
        assert_eq!(built[0].severity, "high");
        assert!(!built[0].remediation.is_empty());
    }

    #[test]
    fn invalid_custom_pattern_returns_error() {
        let defs = vec![CustomRuleDef {
            id: "bad-v1".to_string(),
            provider: "test".to_string(),
            description: None,
            pattern: r"[invalid regex(".to_string(),
            min_entropy: None,
            severity: None,
            remediation: None,
        }];
        let result = build_custom_patterns(&defs);
        assert!(result.is_err());
    }

    // ── AWS Secret Access Key ──────────────────────────────────────────────────

    #[test]
    fn aws_secret_access_key_matches() {
        let p = patterns();
        let body = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef01234567";
        assert_eq!(body.len(), 40);
        assert!(matches(&p, "aws-secret-access-key-v1", &format!("AWS_SECRET_ACCESS_KEY={body}")));
    }

    #[test]
    fn aws_secret_access_key_no_match_without_context() {
        let p = patterns();
        assert!(!matches(&p, "aws-secret-access-key-v1", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef01234567"));
    }

    // ── Azure service principal secret ────────────────────────────────────────

    #[test]
    fn azure_service_principal_secret_matches() {
        let p = patterns();
        let body = "AbCdEfGhIjKlMnOpQrStUvWxYz1234567890AB";
        assert!(matches(&p, "azure-service-principal-secret-v1", &format!("AZURE_CLIENT_SECRET={body}")));
    }

    #[test]
    fn azure_service_principal_no_match_without_context() {
        let p = patterns();
        assert!(!matches(&p, "azure-service-principal-secret-v1", "AbCdEfGhIjKlMnOpQrStUvWxYz1234567890AB"));
    }

    // ── GCP OAuth client secret ───────────────────────────────────────────────

    #[test]
    fn gcp_oauth_client_secret_matches() {
        let p = patterns();
        let body = "AbCdEfGhIjKlMnOpQrStUvWxYZ12"; // 28 chars
        assert_eq!(body.len(), 28);
        assert!(matches(&p, "gcp-oauth-client-secret-v1", &format!("GOCSPX-{body}")));
    }

    #[test]
    fn gcp_oauth_client_secret_no_match_short() {
        let p = patterns();
        assert!(!matches(&p, "gcp-oauth-client-secret-v1", "GOCSPX-short"));
    }

    // ── GitHub App private key ────────────────────────────────────────────────

    #[test]
    fn github_app_private_key_matches() {
        let p = patterns();
        let body = "A".repeat(100);
        let pem = format!("-----BEGIN RSA PRIVATE KEY-----\n{body}\n-----END RSA PRIVATE KEY-----");
        assert!(matches(&p, "github-app-private-key-v1", &pem));
    }

    // ── npm access token ──────────────────────────────────────────────────────

    #[test]
    fn npm_access_token_matches() {
        let p = patterns();
        let body = "AbCdEfGhIjKlMnOpQrStUvWxYz1234567890"; // 36 chars
        assert_eq!(body.len(), 36);
        assert!(matches(&p, "npm-access-token-v1", &format!("npm_{body}")));
    }

    #[test]
    fn npm_access_token_no_match_short() {
        let p = patterns();
        assert!(!matches(&p, "npm-access-token-v1", "npm_short"));
    }

    // ── PyPI API token ────────────────────────────────────────────────────────

    #[test]
    fn pypi_api_token_matches() {
        let p = patterns();
        let body = "AbCdEfGhIjKlMnOpQrStUvWxYz1234567890abcd"; // 40 chars
        assert!(matches(&p, "pypi-api-token-v1", &format!("pypi-{body}")));
    }

    #[test]
    fn pypi_api_token_no_match_short() {
        let p = patterns();
        assert!(!matches(&p, "pypi-api-token-v1", "pypi-short"));
    }

    // ── Docker Hub PAT ────────────────────────────────────────────────────────

    #[test]
    fn docker_hub_pat_matches() {
        let p = patterns();
        let body = "AbCdEfGhIjKlMnOpQrStUvWxYZ"; // 26 chars
        assert_eq!(body.len(), 26);
        assert!(matches(&p, "docker-hub-pat-v1", &format!("dckr_pat_{body}")));
    }

    #[test]
    fn docker_hub_pat_no_match_short() {
        let p = patterns();
        assert!(!matches(&p, "docker-hub-pat-v1", "dckr_pat_sh"));
    }

    // ── Slack webhook URL ─────────────────────────────────────────────────────

    #[test]
    fn slack_webhook_url_matches() {
        let p = patterns();
        assert!(matches(
            &p,
            "slack-webhook-url-v1",
            "https://hooks.slack.com/services/TABCDEFGH1/BABCDEFGH1/AbCdEfGhIjKlMnOpQrStUvWx",
        ));
    }

    #[test]
    fn slack_webhook_url_no_match_wrong_domain() {
        let p = patterns();
        assert!(!matches(
            &p,
            "slack-webhook-url-v1",
            "https://evil.com/services/TABCDEFGH1/BABCDEFGH1/AbCdEfGhIjKlMnOpQrStUvWx",
        ));
    }

    // ── MongoDB connection string ──────────────────────────────────────────────

    #[test]
    fn mongodb_conn_string_matches() {
        let p = patterns();
        assert!(matches(
            &p,
            "mongodb-conn-string-v1",
            "mongodb+srv://myuser:mypassword123@cluster.mongodb.net/mydb",
        ));
    }

    #[test]
    fn mongodb_conn_string_no_match_without_password() {
        let p = patterns();
        assert!(!matches(&p, "mongodb-conn-string-v1", "mongodb://localhost/mydb"));
    }

    // ── PostgreSQL connection string ───────────────────────────────────────────

    #[test]
    fn postgres_conn_string_matches() {
        let p = patterns();
        assert!(matches(
            &p,
            "postgres-conn-string-v1",
            "postgresql://myuser:mypassword@localhost:5432/mydb",
        ));
    }

    #[test]
    fn postgres_conn_string_no_match_without_password() {
        let p = patterns();
        assert!(!matches(&p, "postgres-conn-string-v1", "postgres://myuser@localhost/mydb"));
    }

    // ── Redis URL with password ───────────────────────────────────────────────

    #[test]
    fn redis_url_with_password_matches() {
        let p = patterns();
        assert!(matches(
            &p,
            "redis-url-with-password-v1",
            "redis://:mypassword123@localhost:6379/0",
        ));
    }

    #[test]
    fn redis_url_no_match_without_password() {
        let p = patterns();
        assert!(!matches(&p, "redis-url-with-password-v1", "redis://localhost:6379"));
    }

    // ── JWT secret ────────────────────────────────────────────────────────────

    #[test]
    fn jwt_secret_matches() {
        let p = patterns();
        let body = "mysupersecretjwtkey1234567890abcdefghij"; // 39 chars >= 32
        assert!(matches(&p, "jwt-secret-v1", &format!("JWT_SECRET={body}")));
    }

    #[test]
    fn jwt_secret_no_match_without_context() {
        let p = patterns();
        assert!(!matches(&p, "jwt-secret-v1", "mysupersecretjwtkey1234567890abcdefghij"));
    }

    // ── SSH private key ───────────────────────────────────────────────────────

    #[test]
    fn ssh_private_key_matches() {
        let p = patterns();
        let body = "A".repeat(64);
        let pem = format!("-----BEGIN OPENSSH PRIVATE KEY-----\n{body}\n-----END OPENSSH PRIVATE KEY-----");
        assert!(matches(&p, "ssh-private-key-v1", &pem));
    }

    // ── PEM private key (generic) ─────────────────────────────────────────────

    #[test]
    fn pem_private_key_generic_matches() {
        let p = patterns();
        let body = "A".repeat(64);
        let pem = format!("-----BEGIN PRIVATE KEY-----\n{body}\n-----END PRIVATE KEY-----");
        assert!(matches(&p, "pem-private-key-generic-v1", &pem));
    }

    // ── Confidence tier assignments ───────────────────────────────────────────

    #[test]
    fn openai_legacy_has_high_confidence() {
        let p = patterns();
        let pat = p.iter().find(|x| x.id == "openai-legacy-key-v1").unwrap();
        assert_eq!(pat.confidence, ConfidenceTier::High);
    }

    #[test]
    fn mongodb_pattern_has_high_confidence() {
        let p = patterns();
        let pat = p.iter().find(|x| x.id == "mongodb-conn-string-v1").unwrap();
        assert_eq!(pat.confidence, ConfidenceTier::High);
    }

    #[test]
    fn jwt_pattern_has_medium_confidence() {
        let p = patterns();
        let pat = p.iter().find(|x| x.id == "jwt-secret-v1").unwrap();
        assert_eq!(pat.confidence, ConfidenceTier::Medium);
    }

    #[test]
    fn aws_secret_key_has_medium_confidence() {
        let p = patterns();
        let pat = p.iter().find(|x| x.id == "aws-secret-access-key-v1").unwrap();
        assert_eq!(pat.confidence, ConfidenceTier::Medium);
    }
}
