# Industry-Standard Feature Report for sf-keyaudit

This document captures the highest-value features needed to move sf-keyaudit from a strong CI-focused scanner to an industry-standard key audit tool.

## Current strengths

sf-keyaudit already has a credible core:

- Provider-specific pattern detection for major AI providers
- Entropy-based confidence filtering to reduce false positives
- Ignore-file support and a gitignore-aware walker
- Allowlist support with expiry and stale-entry warnings
- JSON and SARIF output for automation and code scanning platforms
- Clean CI-oriented exit codes and straightforward CLI usage

That foundation is solid. The main gaps are in policy, triage, remediation, verification, and enterprise workflow support.

## Highest-priority features

### 1. Policy and configuration file

Add a checked-in configuration file so teams can define scan policy in the repository instead of encoding behavior in shell scripts.

Recommended capabilities:

- Default providers and scan targets
- Include and exclude path rules
- Severity overrides per pattern or provider
- Confidence and entropy tuning
- Output defaults and CI behavior
- Organization-specific policy settings

Why it matters:

Enterprise teams need stable, reviewable, version-controlled policy. A CLI-only model does not scale cleanly across many repositories and pipelines.

### 2. Git-aware scan modes

Add modes that scan code changes, not only full directory trees.

Recommended capabilities:

- `--staged` to scan staged files before commit
- `--diff-base <REV>` to scan changes relative to a branch or commit
- `--since-commit <REV>` for incremental CI runs
- `--history` for full commit-history scanning

Why it matters:

Most teams want to block newly introduced secrets while separately managing historical debt.

### 3. Baselining for existing findings

Add baseline support so repositories with known findings can adopt the tool without immediately failing every build.

Recommended capabilities:

- Generate a baseline from the current findings
- Ignore baseline findings while failing on newly introduced ones
- Reconcile and prune stale baseline entries
- Record who approved the baseline and when

Why it matters:

Allowlists are useful for targeted exceptions. Baselines are the standard mechanism for onboarding large existing codebases.

### 4. Stable finding fingerprints

Add durable fingerprints for findings so they can be tracked across runs even when line numbers shift.

Recommended capabilities:

- Stable fingerprint per finding
- Fingerprint included in JSON and SARIF output
- Fingerprint-based deduplication and baseline matching

Why it matters:

Sequential IDs like `f-001` are not enough for enterprise triage, dashboards, or longitudinal tracking.

### 5. Secret verification plugins

Add optional provider-aware validation to distinguish likely-real secrets from lookalikes.

Recommended capabilities:

- Offline-safe defaults
- Opt-in network validation
- Provider-specific validation adapters
- Validation result included in report metadata

Why it matters:

Regex plus entropy is strong, but validation reduces false positives further and increases trust in findings.

### 6. Remediation guidance per provider

Detection should be paired with clear remediation actions.

Recommended capabilities:

- Rotation and revocation guidance per provider
- Links to official provider docs
- Suggestions for secret storage replacements
- Remediation text in JSON and SARIF metadata

Why it matters:

Security tools are more useful when they tell users what to do next, not just what went wrong.

## Important next-tier features

### 7. Richer severity and confidence model

Move beyond a single fixed severity.

Recommended capabilities:

- Severity levels based on provider and secret type
- Confidence levels beyond entropy threshold alone
- Distinguish live credential risk from test/example risk

Why it matters:

Not all findings have the same operational impact. Security teams need triage signal.

### 8. Custom rules and organizational rule packs

Allow teams to define internal token formats and custom detection logic.

Recommended capabilities:

- Custom regex rules from config
- Versioned internal rule packs
- Rule metadata such as owner, severity, and remediation

Why it matters:

Industry-standard tools are extensible. Organizations always have internal credentials not covered by public provider patterns.

### 9. Better output schema for security platforms

Expand the machine-readable schema.

Recommended capabilities:

- Fingerprints and stable identifiers
- Confidence and validation status
- Remediation metadata
- Suppression provenance
- Timestamps such as first seen and last seen

Why it matters:

Security platforms, dashboards, and PR workflows need richer structured metadata than a minimal report provides.

### 10. Ownership and blame enrichment

Add lightweight context to route findings quickly.

Recommended capabilities:

- CODEOWNERS mapping
- Last author or commit metadata
- Team ownership in output

Why it matters:

Routing a finding to the right team is often harder than detecting it.

### 11. Structured-file and artifact awareness

Expand beyond plain text scanning.

Recommended capabilities:

- Smarter handling of `.env`, YAML, JSON, TOML, Dockerfiles, and Terraform
- Notebook-aware scanning
- Optional archive scanning for zip and tar artifacts

Why it matters:

Real leaks appear in config files, generated artifacts, and infrastructure definitions, not only source files.

### 12. Performance features for very large repositories

Add controls for monorepo-scale operation.

Recommended capabilities:

- Incremental caching
- Hash-based skip logic
- Worker-count tuning
- Partitioned scan support

Why it matters:

Large enterprise repositories need predictable scan time and lower repeated work.

## Operational maturity features

### 13. Metrics and observability

Logging is one part of this, but operational visibility should be broader.

Recommended capabilities:

- Scan duration and throughput metrics
- Files skipped and reasons
- Findings by provider and confidence
- Baseline vs new finding counts
- Validation success and failure stats

Why it matters:

Security teams need trend data to manage adoption, noise, and policy effectiveness.

### 14. Better triage UX

Improve the developer experience when investigating findings.

Recommended capabilities:

- Human-readable console output mode
- Grouping by file, provider, or severity
- Safe context snippets around matches
- Assisted generation of allowlist or baseline entries

Why it matters:

The tool is currently strong as a gate. It will be stronger when it also helps humans resolve findings efficiently.

### 15. Security hardening and privacy model

Harden the tool itself as a security product.

Recommended capabilities:

- Strong guarantees that raw secrets never appear in logs or errors
- Tests covering stderr and failure paths for redaction safety
- Clear documentation of any validation/network behavior
- Safe handling of temporary artifacts and crash scenarios

Why it matters:

Secret-scanning tools must hold themselves to a high standard around data handling.

## Recommended implementation order

If only a few features are added next, the highest-value sequence is:

1. Policy and configuration file
2. Git-aware scan modes
3. Baselining for existing findings
4. Stable finding fingerprints
5. Richer report metadata

That sequence would move sf-keyaudit from a strong point tool to something much closer to enterprise standard.

## Bottom line

sf-keyaudit already has a strong scanning core. The biggest remaining gap is not raw detection quality, but ecosystem maturity: policy management, onboarding for legacy repos, stable finding lifecycle, verification, remediation, and better integration into security operations.