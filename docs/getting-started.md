# Getting Started

## Requirements

- **Pre-built binary**: no requirements — download and run.
- **Install from source**: Rust toolchain 1.75.0 or newer ([rustup.rs](https://rustup.rs)).

---

## Installation

### From crates.io (recommended)

```sh
cargo install sf-keyaudit
```

This compiles the tool with full optimisations and places the binary in `~/.cargo/bin/`.

### From source

```sh
git clone https://github.com/veerarag1973/sf-keyaudit
cd sf-keyaudit
cargo build --release
# Binary: target/release/sf-keyaudit  (Windows: target/release/sf-keyaudit.exe)
```

### Verify the installation

```sh
sf-keyaudit -V
# sf-keyaudit v2.0.0  |  Copyright © 2026 Spanforge  |  Build <N>
```

---

## Your first scan

### Scan the current directory

```sh
sf-keyaudit
```

The tool walks the working directory recursively, respects `.gitignore` and `.sfignore`, and writes a JSON report to stdout.

### Scan a specific path

```sh
sf-keyaudit ./my-project
```

### Scan a single file

```sh
sf-keyaudit src/config.py
```

---

## Understanding the output

When findings are detected you get a JSON object on stdout and exit code 1:

```json
{
  "scan_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
  "tool": "sf-keyaudit",
  "version": "2.0.0",
  "timestamp": "2026-04-04T10:00:00Z",
  "scan_root": "/home/user/my-project",
  "files_scanned": 120,
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
    "files_skipped": 0,
    "total_raw_matches": 1,
    "high_confidence_count": 1,
    "low_confidence_count": 0,
    "suppressed_count": 0,
    "baselined_count": 0,
    "notebooks_scanned": 0,
    "archives_scanned": 0,
    "cached_files_skipped": 0
  }
}
```

Key points:

- **`findings`** are high-confidence matches (entropy above threshold). These trigger exit code 1.
- **`low_confidence_findings`** are pattern matches whose entropy is too low to be a real key (e.g. placeholder values). These do not trigger exit code 1.
- **`baselined_findings`** are findings suppressed by `--baseline`. They appear in the report for auditing but do not trigger exit code 1.
- The `match` field never contains the raw key value — only a redacted form like `sk-proj-***REDACTED***`.
- `file` paths are always relative to the scan root — safe to log and share.
- `fingerprint` is a stable identifier derived from `pattern_id + file + line`, used for baseline matching and deduplication across runs.
- `validation_status`, `owner`, `last_author` are optional enrichment fields populated by `--verify` and `--owners`.
- `metrics` is always present and reports scan performance counters including notebook, archive, and cache statistics.

When the scan is clean:

```json
{
  "scan_id": "...",
  ...
  "findings": [],
  "low_confidence_findings": [],
  "summary": { "total_findings": 0, "by_provider": {}, "files_with_findings": 0 }
}
```

Exit code: **0**.

---

## Common invocations

| Goal | Command |
|---|---|
| Scan current directory | `sf-keyaudit` |
| Scan a path | `sf-keyaudit ./src` |
| Stop on first finding | `sf-keyaudit --fail-fast .` |
| Only check for OpenAI and Anthropic keys | `sf-keyaudit --providers openai,anthropic .` |
| Write report to a file | `sf-keyaudit --output report.json .` |
| SARIF output for GitHub Code Scanning | `sf-keyaudit --format sarif --output results.sarif .` |
| Human-readable output grouped by severity | `sf-keyaudit --format text --group-by severity .` |
| Suppress known findings | `sf-keyaudit --allowlist .sfkeyaudit-allow.yaml .` |
| Silent CI gate (exit code only) | `sf-keyaudit --quiet --fail-fast .` |
| Scan only staged files (pre-commit) | `sf-keyaudit --staged` |
| Scan PR changes only | `sf-keyaudit --since-commit origin/main .` |
| Generate a baseline file | `sf-keyaudit --generate-baseline .sfkeyaudit-baseline.json .` |
| Suppress baseline findings | `sf-keyaudit --baseline .sfkeyaudit-baseline.json .` |
| Enrich with CODEOWNERS and blame | `sf-keyaudit --owners .` |
| Classify findings with offline validation | `sf-keyaudit --verify .` |
| Scan inside archives | `sf-keyaudit --scan-archives .` |
| Speed up repeated scans | `sf-keyaudit --cache-file .sfkeyaudit-cache.json .` |

---

## Next steps

- [CLI Reference](cli-reference.md) — every flag explained
- [Providers](providers.md) — what credentials are detected
- [Allowlist](allowlist.md) — suppress known-safe findings
- [Baseline](baseline.md) — onboard existing codebases without breaking the build
- [Configuration](config.md) — policy-as-code via `.sfkeyaudit.yaml`
- [CI Integration](ci-integration.md) — hook into your pipeline
- [Output Formats](output-formats.md) — full JSON and SARIF schemas
