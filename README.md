# sf-keyaudit

A fast, CI-friendly command-line tool that scans codebases for exposed AI API keys across all major providers.

Exit 0 when clean. Exit 1 when findings are detected. Designed to drop straight into a pre-push or pre-merge pipeline as a hard gate.

**v2.2.0** adds: 14 new network validators (32 total), a plugin directory system (`--plugin-dir`) for user-supplied detectors, and declarative custom validators in `.sfkeyaudit.yaml`.

**v2.1.0** adds: policy enforcement packs (`--policy-pack`) with per-finding violation records, a fully operational triage store (`sf-keyaudit triage set/list`, `--triage-store`), confidence-tier filtering in policy evaluation (`confidence_min`), and complete audit log wiring (`BaselineGenerated`, `SuppressionCreated`, `ValidationExecuted`, `TriageStateChanged`, `PolicyViolation`).

**v2.0.0** adds: project config files, baselining, incremental git modes, offline verification, CODEOWNERS enrichment, archive and notebook scanning, a hash-based scan cache, text output with grouping, custom rules, and severity overrides.

---

## Why trust this tool

| Signal | Detail |
|---|---|
| Open source | Full source on GitHub — no proprietary components |
| Signed releases | Every release binary ships with a SHA-256 checksum and SLSA Level 2 provenance attestation via GitHub Actions |
| SBOM published | CycloneDX and SPDX SBOMs published with every tagged release |
| Zero-dependency binary | Single statically linked binary; no runtime, no interpreter required |
| CI enforced | Every commit runs `cargo fmt`, `clippy -D warnings`, full test suite, and `cargo audit` |
| Test coverage | 418+ unit tests and 53+ integration tests; property-based tests for core algorithms |
| Security policy | [SECURITY.md](SECURITY.md): coordinated disclosure, response SLA, nightly `cargo audit` |
| Dependency audit | Automated nightly scan for known vulnerabilities and yanked crates |

---

## Supported providers

sf-keyaudit v2.2.0 ships **94 built-in detectors** across 40+ provider families with **32 network validators**. See [Detector Capability Matrix](docs/detector-matrix.md) for the full reference with confidence tiers and validation support.

**AI providers (18 detectors)**

| Provider | Pattern IDs |
|---|---|
| Anthropic | `anthropic-api-key-v1` |
| OpenAI | `openai-project-key-v2`, `openai-svcacct-key-v1`, `openai-legacy-key-v1` |
| OpenRouter | `openrouter-api-key-v1` |
| Stability AI | `stability-ai-key-v1` |
| Google Gemini | `google-gemini-key-v1` |
| Google Vertex AI | `google-vertex-service-account-v1` |
| Cohere | `cohere-api-key-v1` |
| Mistral AI | `mistral-api-key-v1` |
| Hugging Face | `huggingface-token-v1` |
| Replicate | `replicate-api-token-v1` |
| Together AI | `together-ai-key-v1` |
| Groq | `groq-api-key-v1` |
| Perplexity | `perplexity-key-v1` |
| ElevenLabs | `elevenlabs-api-key-v1` |
| Pinecone | `pinecone-api-key-v1` |
| Weaviate | `weaviate-api-key-v1` |

**Cloud platforms (8 detectors)**

| Provider | Pattern IDs |
|---|---|
| AWS | `aws-access-key-id-v1`, `aws-secret-access-key-v1` |
| Azure | `azure-openai-subscription-key-v1`, `azure-service-principal-secret-v1` |
| GCP | `gcp-oauth-client-secret-v1` |
| DigitalOcean | `digitalocean-pat-v1`, `digitalocean-oauth-token-v1` |
| Linode | `linode-api-token-v1` |

**Infrastructure tools (9 detectors)**

| Provider | Pattern IDs |
|---|---|
| HashiCorp Vault | `vault-service-token-v1`, `vault-batch-token-v1`, `vault-root-token-v1` |
| Cloudflare | `cloudflare-api-token-v1`, `cloudflare-global-api-key-v1` |
| Datadog | `datadog-api-key-v1`, `datadog-app-key-v1` |
| Terraform Cloud | `terraform-cloud-token-v1`, `terraform-cloud-env-token-v1` |

**Source control (7 detectors)**

| Provider | Pattern IDs |
|---|---|
| GitHub | `github-fine-grained-pat-v1`, `github-classic-pat-v1`, `github-oauth-token-v1`, `github-actions-token-v1`, `github-refresh-token-v1`, `github-app-private-key-v1` |
| GitLab | `gitlab-pat-v1`, `gitlab-runner-token-v1` |
| Bitbucket | `bitbucket-app-password-v1` |

**Package registries (3 detectors)**

| Provider | Pattern IDs |
|---|---|
| npm | `npm-access-token-v1` |
| PyPI | `pypi-api-token-v1` |
| RubyGems | `rubygems-api-key-v1` |

**Communication & messaging (8 detectors)**

| Provider | Pattern IDs |
|---|---|
| Slack | `slack-bot-token-v1`, `slack-webhook-url-v1` |
| Discord | `discord-bot-token-v1` |
| Telegram | `telegram-bot-token-v1` |
| Twilio | `twilio-account-sid-v1`, `twilio-auth-token-v1` |
| SendGrid | `sendgrid-api-key-v1` |
| Mailgun | `mailgun-api-key-v1` |

**Payment, observability, auth, databases, crypto, CI/CD, SaaS, blockchain (41 detectors)**

| Provider | Pattern IDs |
|---|---|
| Stripe | `stripe-secret-key-v1`, `stripe-restricted-key-v1` |
| Braintree | `paypal-braintree-token-v1` |
| New Relic | `new-relic-license-key-v1`, `new-relic-user-api-key-v1` |
| Sentry | `sentry-dsn-v1` |
| Splunk | `splunk-hec-token-v1` |
| Auth0 | `auth0-client-secret-v1` |
| Okta | `okta-api-token-v1` |
| Firebase | `firebase-server-key-v1` |
| PostgreSQL | `postgres-connection-url-v1` |
| MySQL | `mysql-connection-url-v1` |
| MongoDB | `mongodb-connection-url-v1` |
| Redis | `redis-connection-url-v1` |
| MSSQL | `mssql-connection-string-v1` |
| PKI | `rsa-private-key-v1`, `pgp-private-key-v1`, `ssh-ed25519-private-key-v1` |
| JWT | `jwt-secret-context-v1` |
| CircleCI | `circleci-api-token-v1` |
| Travis CI | `travis-ci-api-token-v1` |
| Jenkins | `jenkins-api-token-v1` |
| Azure DevOps | `azure-devops-pat-v1` |
| Docker Hub | `docker-hub-pat-v1` |
| Heroku | `heroku-api-key-v1` |
| Shopify | `shopify-private-app-token-v1`, `shopify-custom-app-token-v1` |
| PagerDuty | `pagerduty-api-key-v1` |
| Jira | `jira-api-token-v1` |
| Ethereum | `ethereum-private-key-v1` |
| Infura | `infura-api-key-v1` |

---

## Installation

### Prebuilt binaries (fastest)

Download a signed binary for your platform from the [latest GitHub release](https://github.com/veerarag1973/sf-keyaudit/releases/latest).

| Platform | Archive | Checksum |
|---|---|---|
| Linux x86-64 | `sf-keyaudit-linux-x86_64.tar.gz` | `.sha256` alongside |
| macOS arm64 (Apple Silicon) | `sf-keyaudit-macos-arm64.tar.gz` | `.sha256` alongside |
| Windows x86-64 | `sf-keyaudit-windows-x86_64.zip` | `.sha256` alongside |

#### Linux / macOS

```sh
curl -LO https://github.com/veerarag1973/sf-keyaudit/releases/latest/download/sf-keyaudit-linux-x86_64.tar.gz
tar xzf sf-keyaudit-linux-x86_64.tar.gz
sudo mv sf-keyaudit /usr/local/bin/
sf-keyaudit --version
```

#### Windows (PowerShell)

```powershell
Invoke-WebRequest -Uri https://github.com/veerarag1973/sf-keyaudit/releases/latest/download/sf-keyaudit-windows-x86_64.zip -OutFile sf-keyaudit.zip
Expand-Archive sf-keyaudit.zip -DestinationPath $env:LOCALAPPDATA\sf-keyaudit
# Add $env:LOCALAPPDATA\sf-keyaudit to your PATH
sf-keyaudit --version
```

### Via cargo-binstall (no compile)

```sh
cargo binstall sf-keyaudit
```

Installs the prebuilt binary directly. Requires [`cargo-binstall`](https://github.com/cargo-bins/cargo-binstall).

### From crates.io (compile from source)

```sh
cargo install sf-keyaudit
```

### From source

```sh
git clone https://github.com/veerarag1973/sf-keyaudit
cd sf-keyaudit
cargo build --release
# binary is at target/release/sf-keyaudit
```

### Verify a release download

Every release asset ships with a `.sha256` sidecar and a SLSA provenance attestation.

```sh
# 1. Verify the checksum
sha256sum --check sf-keyaudit-linux-x86_64.tar.gz.sha256

# 2. Verify SLSA provenance (requires GitHub CLI ≥ 2.49)
gh attestation verify sf-keyaudit-linux-x86_64.tar.gz \
  --repo veerarag1973/sf-keyaudit

# 3. Inspect the CycloneDX SBOM
curl -LO https://github.com/veerarag1973/sf-keyaudit/releases/latest/download/sf-keyaudit-v2.2.0-sbom.cdx.json
```

The SLSA Level 2 provenance attestation records the exact commit, workflow run, and build environment used to produce each binary.

---

## Quick start

```sh
# Scan the current directory
sf-keyaudit

# Scan a specific path
sf-keyaudit ./my-project

# Scan a single file
sf-keyaudit src/config.py

# Output SARIF (for GitHub Code Scanning)
sf-keyaudit --format sarif --output results.sarif .

# Scan only for specific providers
sf-keyaudit --providers openai,anthropic .

# Stop on the first finding (fast CI gate)
sf-keyaudit --fail-fast .

# Scan only staged files (pre-commit gate)
sf-keyaudit --staged

# Scan files changed since a branch diverged (PR gate)
sf-keyaudit --since-commit origin/main .

# Generate a baseline from existing findings
sf-keyaudit --generate-baseline .sfkeyaudit-baseline.json .

# Suppress baseline findings in subsequent runs
sf-keyaudit --baseline .sfkeyaudit-baseline.json .

# Annotate findings with CODEOWNERS and git blame
sf-keyaudit --owners .

# Classify findings with offline heuristic validation
sf-keyaudit --verify .

# Group human-readable output by severity
sf-keyaudit --format text --group-by severity .

# Speed up repeated scans with a hash cache
sf-keyaudit --cache-file .sfkeyaudit-cache.json .

# Scan inside zip and tar archives
sf-keyaudit --scan-archives .

# Apply a policy pack — exits 1 and emits policy_violations on BLOCK
sf-keyaudit --policy-pack strict-ci .

# Suppress known false positives with a triage decision
sf-keyaudit triage set <fingerprint> false-positive --justification "test fixture"
sf-keyaudit --triage-store .sfkeyaudit-triage.json .

# Write a JSONL audit log for compliance evidence
sf-keyaudit --audit-log audit.jsonl --actor ci-bot --repository org/repo .
```

---

## CLI reference

```
sf-keyaudit [OPTIONS] [PATH]
```

| Flag | Short | Description |
|---|---|---|
| `[PATH]` | | Directory or file to scan. Defaults to the current working directory. |
| `--output <FILE>` | `-o` | Write the report to FILE instead of stdout. |
| `--format <FORMAT>` | | Output format: `json` (default), `sarif`, or `text`. |
| `--fail-fast` | | Stop on the first finding rather than scanning all files. |
| `--no-ignore` | | Disable `.gitignore` and `.sfignore` exclusions — scan everything. |
| `--ignore-file <FILE>` | | Path to a gitignore-style ignore file. Repeatable. |
| `--max-file-size <BYTES>` | | Skip files larger than BYTES. Default: `10485760` (10 MiB). |
| `--max-depth <N>` | | Maximum directory traversal depth. Unlimited by default. |
| `--providers <LIST>` | | Comma-separated provider slugs to scan for. Default: all providers. |
| `--allowlist <FILE>` | | Path to an allowlist YAML file (`.sfkeyaudit-allow.yaml`). |
| `--follow-links` | | Follow symbolic links during traversal. Off by default. |
| `--quiet` | `-q` | Suppress all stdout output. Exit code is the only signal. |
| `--verbose` | `-v` | Print each file path as it is scanned (to stderr). |
| `--threads <N>` | | Number of parallel scan threads. Default: logical CPUs. |
| `--config <FILE>` | | Path to a project config file (`.sfkeyaudit.yaml`). Auto-discovered if omitted. |
| `--plugin-dir <DIR>` | | Load custom detector YAML files from DIR. Repeatable. |
| `--staged` | | Scan only files staged for commit (`git diff --staged`). |
| `--diff-base <GIT_REF>` | | Scan only files changed vs. GIT_REF (`git diff <GIT_REF>`). |
| `--since-commit <REF>` | | Scan files changed between REF and HEAD. Useful for PR gates. |
| `--history` | | Scan every file ever touched in the full git history (slow on large repos). |
| `--generate-baseline <FILE>` | | Write a baseline of current finding fingerprints to FILE. |
| `--baseline <FILE>` | | Suppress findings whose fingerprints appear in the baseline file. |
| `--prune-baseline` | | Remove stale entries from the baseline before writing. Requires `--generate-baseline`. |
| `--verify` | | Annotate findings with offline heuristic validation status. |
| `--owners` | | Enrich findings with CODEOWNERS matches and git blame author. |
| `--scan-archives` | | Scan inside zip, tar, tgz, bz2, and xz archives. |
| `--cache-file <FILE>` | | Load/save a hash-based scan cache to skip unchanged files. |
| `--group-by <FIELD>` | | Group `--format text` output by `file`, `provider`, or `severity`. |
| `--policy-pack <PACK>` | | Apply a named policy pack: `strict-ci`, `developer-friendly`, `enterprise-default`, or `regulated-env`. A policy violation exits 1 with `policy_violations` in the report. |
| `--triage-store <FILE>` | | Path to the triage state store (JSON). Findings with `false-positive` or `accepted-risk` triage states are suppressed from output. |
| `--audit-log <FILE>` | | Append every scan event and triage change to a JSONL audit log for compliance evidence. |
| `--actor <NAME>` | | Identity recorded in the audit log (defaults to `USERNAME`/`USER` env var). |
| `--repository <NAME>` | | Repository slug recorded in the audit log (e.g. `org/repo`). |

**Subcommands**

| Subcommand | Description |
|---|---|
| `install-hooks [--path <DIR>] [--force]` | Write `pre-commit` and `pre-push` git hooks into `<DIR>/.git/hooks/` (defaults to `.`). Skips existing hooks unless `--force` is passed. |
| `triage set <FINGERPRINT> <STATE> [--justification <TEXT>] [--store <FILE>]` | Set the triage state for a finding identified by its fingerprint. Valid states: `open`, `false-positive`, `accepted-risk`, `needs-rotation`, `revoked`, `pending-review`. |
| `triage list [--store <FILE>]` | List all triage decisions currently in the store. |

See the full [CLI Reference](docs/cli-reference.md) for detailed documentation of every flag.

---

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Scan completed — no findings. |
| `1` | One or more findings detected (not suppressed by allowlist). |
| `2` | Configuration or allowlist error; scan did not run. |
| `3` | Scan root unreadable or fatal I/O error; results unreliable. |
| `4` | Scan clean but allowlist has expired or unmatched entries. |

---

## Output formats

### JSON (default)

The JSON report includes enrichment fields and a `metrics` block added in v2.0:

```json
{
  "scan_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
  "tool": "sf-keyaudit",
  "version": "2.1.0",
  "timestamp": "2026-04-04T10:00:00Z",
  "scan_root": "/home/user/my-project",
  "files_scanned": 42,
  "findings": [
    {
      "id": "f-001",
      "fingerprint": "fp-a1b2c3d4e5f6...",
      "provider": "openai",
      "file": "src/config.py",
      "line": 12,
      "column": 14,
      "match": "sk-proj-***REDACTED***",
      "pattern_id": "openai-project-key-v2",
      "severity": "critical",
      "entropy": 4.87,
      "remediation": "Revoke at platform.openai.com/api-keys and rotate all dependent services.",
      "validation_status": "likely-valid",
      "owner": "@backend-team",
      "last_author": "Jane Doe"
    }
  ],
  "low_confidence_findings": [],
  "baselined_findings": [],
  "summary": {
    "total_findings": 1,
    "by_provider": { "openai": 1 },
    "files_with_findings": 1
  },
  "metrics": {
    "scan_duration_ms": 84,
    "files_skipped": 2,
    "total_raw_matches": 3,
    "high_confidence_count": 1,
    "low_confidence_count": 2,
    "suppressed_count": 0,
    "baselined_count": 0,
    "notebooks_scanned": 0,
    "archives_scanned": 0,
    "cached_files_skipped": 0
  }
}
```

The `match` field always contains `***REDACTED***` in place of the secret body — the raw key value never appears in the output.

### SARIF

```sh
sf-keyaudit --format sarif --output results.sarif .
```

Produces a SARIF 2.1.0 document compatible with GitHub Code Scanning, Azure DevOps, and Visual Studio. SARIF result properties include `validationStatus`, `owner`, `lastAuthor`, `firstSeen`, and `lastSeen` when available.

### Text

```sh
sf-keyaudit --format text .
sf-keyaudit --format text --group-by severity .
sf-keyaudit --format text --group-by provider .
```

Human-readable output with optional grouping. Useful for local triage and interactive review.

See [Output Formats](docs/output-formats.md) for the full schema of each format.

---

## Configuration file

A checked-in `.sfkeyaudit.yaml` in the repository root defines scan policy without requiring CLI flags to be duplicated across scripts. The file is auto-discovered by walking up from the scan root; use `--config` to point to it explicitly.

```yaml
providers:
  - openai
  - anthropic
  - aws-bedrock

max_file_size: 5242880     # 5 MiB

ignore_patterns:
  - "tests/fixtures/"
  - "**/*.example.*"

severity_overrides:
  pinecone-api-key-v1: critical
  weaviate-api-key-v1: high

custom_rules:
  - id: acme-internal-token-v1
    provider: acme
    description: "ACME internal service token"
    pattern: 'ACME_TOKEN=(?P<body>[A-Za-z0-9]{32})'
    min_entropy: 3.5
    severity: high
    remediation: "Rotate via the ACME developer portal."
```

See [Configuration](docs/config.md) for the full reference.

---

## Baseline

Onboard large existing codebases without breaking the build immediately:

```sh
# Step 1: generate a baseline from today's findings
sf-keyaudit --generate-baseline .sfkeyaudit-baseline.json .

# Step 2: commit the baseline file
git add .sfkeyaudit-baseline.json
git commit -m "chore: add sf-keyaudit baseline"

# Step 3: subsequent scans only fail on newly introduced secrets
sf-keyaudit --baseline .sfkeyaudit-baseline.json .

# Step 4: keep the baseline tidy — prune removed secrets on update
sf-keyaudit --baseline .sfkeyaudit-baseline.json \
            --generate-baseline .sfkeyaudit-baseline.json \
            --prune-baseline .
```

The baseline stores stable fingerprints derived from `pattern_id + file + line`. When a baselined key is removed and a new one is added elsewhere, the new finding is **not** suppressed.

See [Baseline](docs/baseline.md) for the full reference.

---

## Ignoring files

### `.sfignore`

Place a `.sfignore` file in the root of the scanned directory. It uses the same gitignore pattern syntax.

```gitignore
# .sfignore
tests/fixtures/
*.test.env
docs/
```

### `--ignore-file`

Pass one or more external ignore files on the command line. Repeatable.

```sh
sf-keyaudit --ignore-file .myignore --ignore-file team.gitignore .
```

See [Ignore Files](docs/ignore-files.md) for the full exclusion layer model.

---

## Allowlist

Suppress known-safe findings permanently or until an expiry date.

Create `.sfkeyaudit-allow.yaml` (or any path, then pass it with `--allowlist`):

```yaml
allowlist:
  - pattern_id: openai-legacy-key-v1
    file: tests/fixtures/mock_key.py
    line: 3
    reason: "Test fixture — not a live credential"

  - pattern_id: aws-access-key-id-v1
    file: docs/examples/terraform.tf
    line: 7
    reason: "Example value from AWS docs, not a real key"
    expires: "2027-01-01"
```

| Field | Required | Description |
|---|---|---|
| `pattern_id` | yes | Pattern identifier from the table above. |
| `file` | yes | Path relative to scan root. |
| `line` | yes | 1-indexed line number of the finding. |
| `column` | no | 1-indexed column. Omit to match any column on the line. |
| `reason` | yes | Human-readable justification. Must not be blank. |
| `expires` | no | ISO-8601 date (`YYYY-MM-DD`). Entry becomes inactive after this date. |

Run with the allowlist:

```sh
sf-keyaudit --allowlist .sfkeyaudit-allow.yaml .
```

Exit code 4 is returned when the scan is clean but the allowlist has entries that are expired or that no longer match any finding. Use this to keep allowlists tidy.

See [Allowlist](docs/allowlist.md) for the full reference.

---

## CI integration

### GitHub Actions (fast gate)

```yaml
- name: Scan for exposed API keys
  run: sf-keyaudit --fail-fast --quiet .
```

### Incremental scan on pull requests

```yaml
- name: Scan changes since merge base
  run: sf-keyaudit --since-commit origin/main --quiet .
```

### With SARIF upload

```yaml
- name: Scan (SARIF)
  run: sf-keyaudit --format sarif --output results.sarif . || true

- name: Upload to GitHub Code Scanning
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

### Faster CI with scan cache

```yaml
- name: Cache scan state
  uses: actions/cache@v4
  with:
    path: .sfkeyaudit-cache.json
    key: sfkeyaudit-${{ github.ref }}

- name: Scan
  run: sf-keyaudit --cache-file .sfkeyaudit-cache.json .
```

See [CI Integration](docs/ci-integration.md) for GitLab, Azure DevOps, and pre-commit hook examples.

---

## Always-excluded directories

The following directories are skipped regardless of ignore settings:

`.git`, `node_modules`, `target`, `dist`, `.venv`, `venv`, `vendor`, `__pycache__`, `.mypy_cache`, `.pytest_cache`, `build`, `.next`, `.nuxt`

---

## License

MIT
