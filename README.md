# sf-keyaudit

A fast, CI-friendly command-line tool that scans codebases for exposed AI API keys across all major providers.

Exit 0 when clean. Exit 1 when findings are detected. Designed to drop straight into a pre-push or pre-merge pipeline as a hard gate.

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
| `--format <FORMAT>` | | Output format: `json` (default) or `sarif`. |
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

```json
{
  "scan_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
  "tool": "sf-keyaudit",
  "version": "1.0.0",
  "timestamp": "2026-04-03T10:00:00Z",
  "scan_root": "/home/user/my-project",
  "files_scanned": 42,
  "findings": [
    {
      "id": "f-001",
      "provider": "openai",
      "file": "src/config.py",
      "line": 12,
      "column": 14,
      "match": "sk-proj-***REDACTED***",
      "pattern_id": "openai-project-key-v2",
      "severity": "critical",
      "entropy": 4.87
    }
  ],
  "low_confidence_findings": [],
  "summary": {
    "total_findings": 1,
    "by_provider": { "openai": 1 },
    "files_with_findings": 1
  }
}
```

The `match` field always contains `***REDACTED***` in place of the secret body — the raw key value never appears in the output.

### SARIF

```sh
sf-keyaudit --format sarif --output results.sarif .
```

Produces a SARIF 2.1.0 document compatible with GitHub Code Scanning, Azure DevOps, and Visual Studio.

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

---

## CI integration

### GitHub Actions

```yaml
name: Secret scan
on: [push, pull_request]

jobs:
  keyaudit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install sf-keyaudit
        run: cargo install sf-keyaudit

      - name: Scan for exposed API keys
        run: sf-keyaudit --fail-fast --quiet .
```

To upload SARIF results to GitHub Code Scanning:

```yaml
      - name: Scan (SARIF)
        run: sf-keyaudit --format sarif --output results.sarif . || true

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

---

## Always-excluded directories

The following directories are skipped regardless of ignore settings:

`.git`, `node_modules`, `target`, `dist`, `.venv`, `venv`, `vendor`, `__pycache__`, `.mypy_cache`, `.pytest_cache`, `build`, `.next`, `.nuxt`

---

## License

MIT
