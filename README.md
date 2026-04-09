# sf-keyaudit

A fast, CI-friendly command-line tool that scans codebases for exposed AI API keys across all major providers.

Exit 0 when clean. Exit 1 when findings are detected. Designed to drop straight into a pre-push or pre-merge pipeline as a hard gate.

**v2.0.0** adds: project config files, baselining, incremental git modes, offline verification, CODEOWNERS enrichment, archive and notebook scanning, a hash-based scan cache, text output with grouping, custom rules, and severity overrides.

---

## Supported providers

| Provider | Pattern IDs |
|---|---|
| Anthropic | `anthropic-api-key-v1` |
| OpenAI | `openai-project-key-v2`, `openai-svcacct-key-v1`, `openai-legacy-key-v1` |
| OpenRouter | `openrouter-api-key-v1` |
| Stability AI | `stability-ai-key-v1` |
| Google Gemini | `google-gemini-key-v1` |
| Google Vertex AI | `google-vertex-service-account-v1` |
| AWS Bedrock | `aws-access-key-id-v1` |
| Azure OpenAI | `azure-openai-subscription-key-v1` |
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
| Stripe | `stripe-live-secret-key-v1`, `stripe-restricted-key-v1` |
| Slack | `slack-bot-token-v1`, `slack-user-token-v1` |
| GitHub | `github-fine-grained-pat-v1`, `github-classic-pat-v1`, `github-oauth-token-v1` |
| GitLab | `gitlab-pat-v1` |
| SendGrid | `sendgrid-api-key-v1` |
| Twilio | `twilio-account-sid-v1`, `twilio-auth-token-v1` |

---

## Installation

### From crates.io

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

**Subcommands**

| Subcommand | Description |
|---|---|
| `install-hooks [--path <DIR>] [--force]` | Write `pre-commit` and `pre-push` git hooks into `<DIR>/.git/hooks/` (defaults to `.`). Skips existing hooks unless `--force` is passed. |

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
  "version": "2.0.0",
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
