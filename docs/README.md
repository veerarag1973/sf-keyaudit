# sf-keyaudit Documentation

**Spanforge Key Audit** — a fast, CI-ready secret scanner for AI provider credentials.

---

## Contents

| Document | Description |
|---|---|
| [Getting Started](getting-started.md) | Installation, first scan, understanding output |
| [CLI Reference](cli-reference.md) | Every flag, argument, and default value |
| [Providers](providers.md) | All 18 supported providers, pattern IDs, and key formats |
| [Output Formats](output-formats.md) | Complete JSON and SARIF 2.1.0 schemas |
| [Allowlist](allowlist.md) | Suppress known-safe findings with YAML rules |
| [Ignore Files](ignore-files.md) | .sfignore, .gitignore, --ignore-file, --no-ignore |
| [Exit Codes](exit-codes.md) | All 5 exit codes and how to use them in scripts |
| [CI Integration](ci-integration.md) | GitHub Actions, GitLab CI, Azure DevOps, pre-commit hooks |
| [Entropy & Confidence](entropy-confidence.md) | How entropy filtering works and what low-confidence means |
| [Baseline](baseline.md) | Onboard existing codebases; generate, use, and prune baseline files |
| [Configuration](config.md) | Policy-as-code via `.sfkeyaudit.yaml`; custom rules and severity overrides |
| [Architecture](architecture.md) | Internal design, module map, and data flow |
