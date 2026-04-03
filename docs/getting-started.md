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
# sf-keyaudit v1.0.0  |  Copyright © 2026 Spanforge  |  Build <N>
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
  "version": "1.0.0",
  "timestamp": "2026-04-03T10:00:00Z",
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

Key points:

- **`findings`** are high-confidence matches (entropy above threshold). These trigger exit code 1.
- **`low_confidence_findings`** are pattern matches whose entropy is too low to be a real key (e.g. placeholder values). These do not trigger exit code 1.
- The `match` field never contains the raw key value — only a redacted form like `sk-proj-***REDACTED***`.
- `file` paths are always relative to the scan root — safe to log and share.

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
| Suppress known findings | `sf-keyaudit --allowlist .sfkeyaudit-allow.yaml .` |
| Silent CI gate (exit code only) | `sf-keyaudit --quiet --fail-fast .` |

---

## Next steps

- [CLI Reference](cli-reference.md) — every flag explained
- [Providers](providers.md) — what credentials are detected
- [Allowlist](allowlist.md) — suppress known-safe findings
- [CI Integration](ci-integration.md) — hook into your pipeline
