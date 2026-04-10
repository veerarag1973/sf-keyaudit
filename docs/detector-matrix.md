# Detector Capability Matrix

sf-keyaudit v2.2.0 ships **94 built-in detectors** across AI providers, source control, package registries, communication services, payment processors, cloud platforms, observability tools, authentication providers, databases, cryptographic material, CI/CD, cloud/SaaS, and blockchain.

## Column definitions

| Column | Meaning |
|---|---|
| **Pattern ID** | Stable identifier passed to `--providers` filter and used in JSON/SARIF output |
| **Provider** | Slug that appears in `Finding.provider` |
| **Severity** | `critical` / `high` / `medium` |
| **Confidence** | `high` = prefix-anchored, unambiguous token format; `medium` = context-sensitive (env var name required) |
| **Offline check** | Format / entropy validation performed without network access |
| **Network check** | Real credential probe (requires `--verify`; network-callable providers only) |
| **Notes** | Key matching characteristic |

---

## AI providers

| Pattern ID | Provider | Severity | Confidence | Offline | Network | Notes |
|---|---|---|---|---|---|---|
| `anthropic-api-key-v1` | `anthropic` | critical | High | ✅ | ✅ | `sk-ant-api03-` prefix, 93-char body |
| `openai-project-key-v2` | `openai` | critical | High | ✅ | ✅ | `sk-proj-` prefix, 100–200 char body |
| `openai-svcacct-key-v1` | `openai` | critical | High | ✅ | ✅ | `sk-svcacct-` prefix |
| `openrouter-api-key-v1` | `openrouter` | high | High | ✅ | ✅ | `sk-or-` prefix |
| `openai-legacy-key-v1` | `openai` | critical | High | ✅ | ✅ | `sk-` prefix (excludes modern prefixes), 48 chars |
| `stability-ai-key-v1` | `stability-ai` | high | Medium | ✅ | — | Requires `STABILITY_API_KEY` variable context |
| `google-gemini-key-v1` | `google-gemini` | critical | High | ✅ | ✅ | `AIza` prefix, 39 chars total |
| `google-vertex-service-account-v1` | `google-vertex-ai` | critical | Medium | ✅ | — | JSON service-account blob with `type:service_account` |
| `cohere-api-key-v1` | `cohere` | high | High | ✅ | ✅ | `co-` prefix |
| `mistral-api-key-v1` | `mistral-ai` | high | High | ✅ | ✅ | `mi-` prefix |
| `huggingface-token-v1` | `huggingface` | high | High | ✅ | ✅ | `hf_` prefix |
| `replicate-api-token-v1` | `replicate` | high | High | ✅ | ✅ | `r8_` prefix, 40-char hex |
| `together-ai-key-v1` | `together-ai` | high | Medium | ✅ | — | Requires `TOGETHER_API_KEY` context |
| `groq-api-key-v1` | `groq` | high | High | ✅ | ✅ | `gsk_` prefix, 52-char body |
| `perplexity-key-v1` | `perplexity` | high | High | ✅ | — | `pplx-` prefix |
| `elevenlabs-api-key-v1` | `elevenlabs` | medium | Medium | ✅ | — | Requires `xi-api-key` header or `ELEVENLABS_API_KEY` context |
| `pinecone-api-key-v1` | `pinecone` | medium | Medium | ✅ | — | UUID format, requires `PINECONE_API_KEY` context |
| `weaviate-api-key-v1` | `weaviate` | medium | Medium | ✅ | — | Requires `X-Weaviate-Api-Key` or `WEAVIATE_API_KEY` context |

---

## Cloud platforms

| Pattern ID | Provider | Severity | Confidence | Offline | Network | Notes |
|---|---|---|---|---|---|---|
| `aws-access-key-id-v1` | `aws-bedrock` | critical | High | ✅ | ✅ | `AKIA` / `ASIA` prefix, 16-char uppercase body |
| `aws-secret-access-key-v1` | `aws` | critical | Medium | ✅ | — | Requires `AWS_SECRET_ACCESS_KEY` context; 40-char base64 |
| `azure-openai-subscription-key-v1` | `azure-openai` | critical | Medium | ✅ | — | Requires `Ocp-Apim-Subscription-Key` header context |
| `azure-service-principal-secret-v1` | `azure` | critical | Medium | ✅ | — | Requires `AZURE_CLIENT_SECRET` context |
| `gcp-oauth-client-secret-v1` | `gcp` | high | High | ✅ | — | `GOCSPX-` prefix |
| `digitalocean-pat-v1` | `digitalocean` | critical | High | ✅ | ✅ | `dop_v1_` prefix, 64-char hex |
| `digitalocean-oauth-token-v1` | `digitalocean` | critical | High | ✅ | ✅ | `doo_v1_` prefix, 64-char hex |
| `linode-api-token-v1` | `linode` | critical | Medium | ✅ | — | Requires `LINODE_TOKEN` / `LINODE_API_KEY` context |

---

## Infrastructure tools

| Pattern ID | Provider | Severity | Confidence | Offline | Network | Notes |
|---|---|---|---|---|---|---|
| `vault-service-token-v1` | `hashicorp-vault` | critical | High | ✅ | — | `hvs.` prefix, 24–100 char base64url body |
| `vault-batch-token-v1` | `hashicorp-vault` | high | High | ✅ | — | `hvb.` prefix, 100–300 char body |
| `vault-root-token-v1` | `hashicorp-vault` | critical | Medium | ✅ | — | `hvr.` or `s.` prefix, requires `VAULT_TOKEN` context |
| `cloudflare-api-token-v1` | `cloudflare` | critical | Medium | ✅ | ✅ | Requires `CLOUDFLARE_API_TOKEN` context; 40-char body |
| `cloudflare-global-api-key-v1` | `cloudflare` | critical | Medium | ✅ | — | Requires `CLOUDFLARE_API_KEY` context; 37-char hex |
| `datadog-api-key-v1` | `datadog` | high | Medium | ✅ | ✅ | Requires `DD_API_KEY` context; 32-char hex |
| `datadog-app-key-v1` | `datadog` | high | Medium | ✅ | — | Requires `DD_APP_KEY` context; 40-char hex |
| `terraform-cloud-token-v1` | `terraform-cloud` | critical | High | ✅ | — | `tf-` or `atlas-` prefix |
| `terraform-cloud-env-token-v1` | `terraform-cloud` | critical | Medium | ✅ | — | Requires `TFC_TOKEN` / `ATLAS_TOKEN` context |

---

## Source control

| Pattern ID | Provider | Severity | Confidence | Offline | Network | Notes |
|---|---|---|---|---|---|---|
| `github-classic-pat-v1` | `github` | critical | High | ✅ | ✅ | `ghp_` prefix, 36-char body |
| `github-fine-grained-pat-v1` | `github` | critical | High | ✅ | ✅ | `github_pat_` prefix, 82-char body |
| `github-oauth-token-v1` | `github` | critical | High | ✅ | — | `gho_` prefix, 36-char body |
| `github-actions-token-v1` | `github` | high | High | ✅ | — | `ghs_` prefix; short-lived Actions token |
| `github-refresh-token-v1` | `github` | critical | High | ✅ | — | `ghr_` prefix, 76-char body |
| `github-app-private-key-v1` | `github` | critical | High | ✅ | — | PEM `BEGIN RSA PRIVATE KEY` block |
| `gitlab-pat-v1` | `gitlab` | critical | High | ✅ | ✅ | `glpat-` prefix, 20-char body |
| `gitlab-runner-token-v1` | `gitlab` | high | High | ✅ | — | `glrt-` prefix, 20-char body |
| `bitbucket-app-password-v1` | `bitbucket` | critical | Medium | ✅ | — | Requires `BITBUCKET_APP_PASSWORD` context |

---

## Package registries

| Pattern ID | Provider | Severity | Confidence | Offline | Network | Notes |
|---|---|---|---|---|---|---|
| `npm-access-token-v1` | `npm` | critical | High | ✅ | ✅ | `npm_` prefix, 36-char body |
| `pypi-api-token-v1` | `pypi` | critical | High | ✅ | — | `pypi-` prefix, 100–200 char body |
| `rubygems-api-key-v1` | `rubygems` | critical | High | ✅ | — | `rubygems_` prefix, 48-char hex |

---

## Communication & messaging

| Pattern ID | Provider | Severity | Confidence | Offline | Network | Notes |
|---|---|---|---|---|---|---|
| `slack-bot-token-v1` | `slack` | critical | High | ✅ | — | `xoxb-` prefix |
| `slack-webhook-url-v1` | `slack` | high | High | ✅ | — | `hooks.slack.com/services/` URL |
| `discord-bot-token-v1` | `discord` | critical | High | ✅ | ✅ | Three-segment dot-separated token; high entropy |
| `telegram-bot-token-v1` | `telegram` | high | High | ✅ | ✅ | Numeric ID `:` alphanumeric body |
| `twilio-account-sid-v1` | `twilio` | high | Medium | ✅ | — | `AC` + 32 hex chars |
| `twilio-auth-token-v1` | `twilio` | critical | Medium | ✅ | — | Requires `TWILIO_AUTH_TOKEN` context; 32-char hex |
| `sendgrid-api-key-v1` | `sendgrid` | critical | High | ✅ | ✅ | `SG.` prefix, two base64url segments |
| `mailgun-api-key-v1` | `mailgun` | critical | High | ✅ | ✅ | `key-` prefix, 32-char hex |

---

## Payment processors

| Pattern ID | Provider | Severity | Confidence | Offline | Network | Notes |
|---|---|---|---|---|---|---|
| `stripe-secret-key-v1` | `stripe` | critical | High | ✅ | ✅ | `sk_live_` prefix |
| `stripe-restricted-key-v1` | `stripe` | critical | High | ✅ | — | `rk_live_` prefix |
| `paypal-braintree-token-v1` | `braintree` | critical | High | ✅ | — | `access_token$production$` prefix |

---

## Observability & monitoring

| Pattern ID | Provider | Severity | Confidence | Offline | Network | Notes |
|---|---|---|---|---|---|---|
| `new-relic-license-key-v1` | `new-relic` | critical | High | ✅ | ✅ | `NRAK-` prefix, 27-char uppercase body |
| `new-relic-user-api-key-v1` | `new-relic` | critical | High | ✅ | ✅ | `NRUA-` prefix |
| `sentry-dsn-v1` | `sentry` | high | Medium | ✅ | ✅ | Requires `SENTRY_DSN` / `SENTRY_AUTH_TOKEN` context |
| `splunk-hec-token-v1` | `splunk` | critical | Medium | ✅ | — | Requires `SPLUNK_TOKEN` / `SPLUNK_HEC_TOKEN` context |

---

## Authentication & identity

| Pattern ID | Provider | Severity | Confidence | Offline | Network | Notes |
|---|---|---|---|---|---|---|
| `auth0-client-secret-v1` | `auth0` | critical | Medium | ✅ | — | Requires `AUTH0_CLIENT_SECRET` context |
| `okta-api-token-v1` | `okta` | critical | Medium | ✅ | — | Requires `OKTA_API_TOKEN` context; `00` prefix |
| `firebase-server-key-v1` | `firebase` | critical | High | ✅ | — | `AAAA` prefix, 140+ char body |

---

## Database connection strings

| Pattern ID | Provider | Severity | Confidence | Offline | Network | Notes |
|---|---|---|---|---|---|---|
| `postgres-connection-url-v1` | `postgres` | critical | High | ✅ | — | `postgres://user:pass@host` URI |
| `mysql-connection-url-v1` | `mysql` | critical | High | ✅ | — | `mysql://user:pass@host` URI |
| `mongodb-connection-url-v1` | `mongodb` | critical | High | ✅ | — | `mongodb+srv://user:pass@host` URI |
| `redis-connection-url-v1` | `redis` | critical | High | ✅ | — | `redis://:pass@host` URI |
| `mssql-connection-string-v1` | `mssql` | critical | Medium | ✅ | — | `Password=` / `PWD=` in ADO.NET connection string |

---

## Cryptographic material

| Pattern ID | Provider | Severity | Confidence | Offline | Network | Notes |
|---|---|---|---|---|---|---|
| `rsa-private-key-v1` | `pki` | critical | High | ✅ | — | `-----BEGIN (RSA\|EC\|DSA) PRIVATE KEY-----` PEM header |
| `pgp-private-key-v1` | `pki` | critical | High | ✅ | — | `-----BEGIN PGP PRIVATE KEY BLOCK-----` |
| `ssh-ed25519-private-key-v1` | `pki` | critical | High | ✅ | — | `-----BEGIN OPENSSH PRIVATE KEY-----` |
| `jwt-secret-context-v1` | `jwt` | critical | Medium | ✅ | — | Requires `JWT_SECRET` / `JWT_SIGNING_KEY` context |

---

## CI/CD & DevOps

| Pattern ID | Provider | Severity | Confidence | Offline | Network | Notes |
|---|---|---|---|---|---|---|
| `circleci-api-token-v1` | `circleci` | critical | Medium | ✅ | — | Requires `CIRCLECI_TOKEN` context; 40-char hex |
| `travis-ci-api-token-v1` | `travisci` | critical | Medium | ✅ | — | Requires `TRAVIS_TOKEN` context; 22-char body |
| `jenkins-api-token-v1` | `jenkins` | critical | Medium | ✅ | — | Requires `JENKINS_TOKEN` context; 32-char hex |
| `azure-devops-pat-v1` | `azure-devops` | critical | Medium | ✅ | — | Requires `AZURE_DEVOPS_TOKEN` / `AZDO_PAT` context; 52 chars |

---

## Cloud & SaaS applications

| Pattern ID | Provider | Severity | Confidence | Offline | Network | Notes |
|---|---|---|---|---|---|---|
| `heroku-api-key-v1` | `heroku` | critical | Medium | ✅ | ✅ | Requires `HEROKU_API_KEY` context; UUID format |
| `shopify-private-app-token-v1` | `shopify` | critical | High | ✅ | — | `shppa_` prefix, 32-char hex |
| `shopify-custom-app-token-v1` | `shopify` | critical | High | ✅ | — | `shpat_` prefix, 32-char hex |
| `pagerduty-api-key-v1` | `pagerduty` | critical | Medium | ✅ | ✅ | Requires `PAGERDUTY_TOKEN` context |
| `jira-api-token-v1` | `jira` | critical | Medium | ✅ | — | Requires `JIRA_API_TOKEN` / `ATLASSIAN_TOKEN` context |

---

## Blockchain & Web3

| Pattern ID | Provider | Severity | Confidence | Offline | Network | Notes |
|---|---|---|---|---|---|---|
| `ethereum-private-key-v1` | `ethereum` | critical | Medium | ✅ | — | `0x` prefix, 64-char hex (256-bit key) |
| `infura-api-key-v1` | `infura` | high | Medium | ✅ | — | Requires `INFURA_KEY` / `INFURA_PROJECT_ID` context |

---

## Summary counts

| Category | Count |
|---|---|
| AI providers | 18 |
| Cloud platforms | 8 |
| Infrastructure tools | 9 |
| Source control | 7 |
| Package registries | 3 |
| Communication & messaging | 8 |
| Payment processors | 3 |
| Observability & monitoring | 4 |
| Authentication & identity | 3 |
| Database connection strings | 5 |
| Cryptographic material | 4 |
| CI/CD & DevOps | 4 |
| Cloud & SaaS applications | 5 |
| Blockchain & Web3 | 2 |
| **Total** | **94** |

---

## Network validation support

Network validation is performed when `--verify` is passed. It makes a lightweight, read-only API call to test whether the credential is currently active. No data is written to the provider; the call uses the minimum required permission scope.

Providers with ✅ in the **Network** column above support active validation. All others use offline format + entropy checks only.

> **Rate limiting**: sf-keyaudit applies a per-provider rate limiter (default: 1 req/s, configurable via `--verify-rate-limit`). Avoid scanning large repositories with `--verify` in CI pipelines with strict API quota limits.

---

## Adding custom detectors

You can define organisation-specific detectors in `.sfkeyaudit.yaml`:

```yaml
custom_rules:
  - id: "internal-service-token-v1"
    provider: "internal"
    description: "Internal platform service token"
    pattern: '(?P<prefix>svc-)(?P<body>[A-Za-z0-9]{32})'
    severity: "critical"
    min_entropy: 4.0
    remediation: "Rotate via the internal secrets portal."
```

Custom rules are appended to the built-in catalog after all built-in patterns. See [docs/config.md](config.md) for full configuration options.
