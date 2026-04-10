# sf-keyaudit Documentation

**Spanforge Key Audit** — a fast, CI-ready secret scanner for AI provider credentials and infrastructure secrets.

---

## Contents

| Document | Description |
|---|---|
| [Executive Overview](executive-overview.md) | Plain-English introduction: what it does, why it matters, and business benefits |
| [Getting Started](getting-started.md) | Installation, first scan, understanding output |
| [CLI Reference](cli-reference.md) | Every flag, argument, and default value |
| [Providers](providers.md) | All supported providers, pattern IDs, and key formats |
| [Detector Matrix](detector-matrix.md) | Full table of all built-in detectors with severity, confidence, and validation support |
| [Output Formats](output-formats.md) | Complete JSON and SARIF 2.1.0 schemas |
| [Allowlist](allowlist.md) | Suppress known-safe findings with YAML rules |
| [Ignore Files](ignore-files.md) | .sfignore, .gitignore, --ignore-file, --no-ignore |
| [Exit Codes](exit-codes.md) | All 5 exit codes and how to use them in scripts |
| [CI Integration](ci-integration.md) | GitHub Actions, GitLab CI, Azure DevOps, pre-commit hooks, policy enforcement |
| [Entropy & Confidence](entropy-confidence.md) | How entropy filtering works and what low-confidence means |
| [Baseline](baseline.md) | Onboard existing codebases; generate, use, and prune baseline files |
| [Configuration](config.md) | Policy-as-code via `.sfkeyaudit.yaml`; custom rules and severity overrides |
| [Architecture](architecture.md) | Internal design, module map, and data flow |
| [Benchmarks](benchmarks.md) | Performance reference: scan throughput, cache impact, and methodology |
| [Artifact Hardening](artifact-hardening.md) | Harden report files, baselines, audit logs, and release binaries |
| [Release Checklist](release-checklist.md) | 7-phase pre/post-release quality process |
| [Platform Maturity Roadmap](platform-maturity-roadmap.md) | Current assessment and phased investment plan |
