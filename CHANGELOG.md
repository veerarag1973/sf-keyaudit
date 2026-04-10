# Changelog

All notable changes to sf-keyaudit are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions follow [Semantic Versioning](https://semver.org/).

---

## [2.2.0] — 2026-04-10

### Added

**Verified-secret validation (18 → 32 validators)**
- New network validators: Twilio, Datadog, New Relic, Sentry, PagerDuty, Discord, Telegram, Mailgun, Heroku, DigitalOcean, npm, PyPI, Cloudflare, Okta
- `ValidatorRunner.register()` method for dynamic validator registration
- Declarative HTTP validator config via `custom_validators` in `.sfkeyaudit.yaml`
- Support for 4 auth methods: `bearer`, `basic_auth`, `header`, `query_param`

**Plugin system**
- `--plugin-dir <DIR>` CLI flag (repeatable) for loading external detection rules
- `plugin_dirs` config field for directory-based plugin rule loading
- Each `.yaml`/`.yml` file in a plugin directory is a list of `CustomRuleDef` entries
- Plugin rules take priority over built-in patterns

---

## [2.1.0] — 2026-04-10

### Added

**Detectors (55 → 94)**
- Source control: GitHub PAT classic/fine-grained (`ghp_`/`github_pat_`), GitHub OAuth (`gho_`), GitHub Actions (`ghs_`), GitHub refresh (`ghr_`), GitLab PAT (`glpat-`), GitLab runner token (`glrt-`), Bitbucket app password
- Package registries: npm access token (`npm_`), PyPI API token (`pypi-`), RubyGems API key (`rubygems_`)
- Communication: Slack bot/user token (`xoxb-`/`xoxp-`), Slack webhook URL, Discord bot token, Telegram bot token, Twilio account SID / auth token, SendGrid API key (`SG.`), Mailgun API key (`key-`)
- Payment: Stripe secret key (`sk_live_`), Stripe restricted key (`rk_live_`), Braintree access token
- Cloud: DigitalOcean PAT (`dop_v1_`) and OAuth token (`doo_v1_`), Linode API token
- Observability: New Relic license key (`NRAK-`) and user API key (`NRUA-`), Sentry DSN/auth token, Splunk HEC token
- Auth/Identity: Auth0 client secret, Okta API token, Firebase server key (`AAAA` prefix)
- Databases: PostgreSQL, MySQL/MariaDB, MongoDB, Redis/Valkey connection URLs; MSSQL connection string
- Cryptographic material: RSA/EC/DSA/OpenSSH private key PEM headers (`-----BEGIN … PRIVATE KEY-----`), PGP private key block, JWT signing secret
- CI/CD: CircleCI API token, Travis CI API token, Jenkins API token, Azure DevOps PAT
- Cloud/SaaS: Heroku API key, Shopify private/custom app tokens (`shppa_`/`shpat_`), PagerDuty API key, Jira/Atlassian API token
- Blockchain/Web3: Ethereum raw private key (0x-prefixed), Infura project key
- HashiCorp Vault: service token (`hvs.`), batch token (`hvb.`), root token, context-sensitive env var
- Cloudflare: API token and global API key (context-sensitive)
- Datadog: API key and application key (context-sensitive)
- Terraform Cloud: prefix-anchored token (`tf-`/`atlas-`) and env-var context token

**Engineering / Quality**
- Zero compiler warnings — `cargo clippy -D warnings` enforced in CI
- Property-based tests using `proptest` covering entropy bounds, fingerprint determinism/uniqueness/hex format, redaction sentinel, and JSON roundtrip (`tests/property_tests.rs`)
- `secret-scan` CI job that builds and runs sf-keyaudit against itself and uploads SARIF to GitHub Advanced Security for PR annotations
- `CONTRIBUTING.md` with full contributor workflow, detector-writing guide, and validator guide
- `CHANGELOG.md` (this file)

**Documentation**
- `docs/detector-matrix.md` — reference table for all built-in detectors
- `docs/benchmarks.md` — performance reference for small/medium/large repos
- `docs/artifact-hardening.md` — report, baseline, audit log, and binary hardening guide
- `docs/release-checklist.md` — 7-phase release process

**Release engineering**
- SHA-256 checksums for all binary release artifacts
- SLSA provenance attestation via `actions/attest-build-provenance@v2`
- CycloneDX SBOM (JSON) via `cargo-cyclonedx`
- SPDX SBOM via `anchore/sbom-action`
- Release binaries for Linux x86_64/aarch64, macOS aarch64, Windows x86_64, and container image

### Changed

- Bumped version `2.0.0` → `2.1.0`
- `docs/platform-maturity-roadmap.md` updated to reflect all completed v2.1.0 items
- `docs/getting-started.md` next-steps links deduplicated; added link to detector matrix
- `docs/cli-reference.md` version example updated to v2.1.0

### Fixed

- `baseline::apply_partitions_correctly` test used non-existent `apply()` method; corrected to `apply_enriched()`
- `entropy::low_entropy_placeholder_below_threshold` / `real_looking_key_above_threshold` tests referenced non-existent `is_high_confidence()`; replaced with direct `shannon_entropy() >= HIGH_CONFIDENCE_THRESHOLD` comparisons
- `patterns::custom_pattern_defaults_applied` test hardcoded `3.0` as default entropy but actual default is `HIGH_CONFIDENCE_THRESHOLD` (3.5); fixed to use the constant

---

## [2.0.0] — 2026-03-15

### Added

**Policy engine**
- `--policy-pack` flag supporting built-in packs: `strict-ci`, `developer-friendly`, `enterprise-default`, `regulated-env`
- Policy evaluation engine with `BLOCK` / `WARN` decisions
- `policy_violations` array in JSON and SARIF output
- `POLICY:` section in text output

**Triage lifecycle**
- `triage set <FINGERPRINT> <STATE>` subcommand
- `triage list` subcommand
- `--triage-store <FILE>` flag for scan-time decoration
- Six triage states: `open`, `acknowledged`, `false_positive`, `accepted_risk`, `revoked_pending_removal`, `fixed`
- `triage_state` and `triage_justification` fields in all output formats

**Audit logging**
- `--audit-log <FILE>` flag writing append-only JSONL
- `--actor <IDENTITY>` and `--repository <REPO>` flags for event provenance
- Seven event types: `ScanStarted`, `ScanCompleted`, `FindingDetected`, `SuppressionCreated`, `ValidationExecuted`, `PolicyViolation`, `BaselineGenerated`, `TriageStateChanged`

**Detector confidence tiers**
- `ConfidenceTier` enum (`High`, `Medium`, `Low`) added to `Pattern` and `Finding`
- `confidence` field in JSON, SARIF, and text output
- `confidence_min` filter in policy configuration

### Changed

- `build_patterns()` now returns patterns in priority order (more specific before general)
- SARIF output includes `suppressions` array for baselined findings
- Baseline entries store `approved_by` and `suppression_provenance` metadata

---

## [1.0.0] — 2026-01-20

### Added

Initial public release.

**Scanning**
- Recursive directory walk with `.gitignore` / `.sfignore` / `.git/info/exclude` / global gitignore support
- 24 built-in AI provider detectors (Anthropic, OpenAI, OpenRouter, Stability AI, Google Gemini/Vertex AI, AWS Bedrock, Azure OpenAI, Cohere, Mistral AI, Hugging Face, Replicate, Together AI, Groq, Perplexity, ElevenLabs, Pinecone, Weaviate)
- Shannon entropy filtering with per-pattern thresholds
- Archive scanning: `.zip`, `.tar`, `.tar.gz`, `.tgz`, `.tar.bz2`, `.tar.xz`
- Jupyter notebook scanning (`.ipynb` code cell extraction)

**Git-aware modes**
- `--staged` — scan only staged files (pre-commit use case)
- `--diff-base <REF>` — scan only files changed relative to a ref
- `--since-commit <REF>` — scan only files changed since a commit
- `--history` — scan all blobs in full git history

**Suppression**
- YAML allowlist (`--allowlist`)
- Baseline generation, suppression, pruning, and merging (`--generate-baseline`, `--baseline`, `--prune-baseline`)

**Output**
- JSON output (default) with full finding schema
- SARIF 2.1.0 output with rules, locations, fingerprints, and suppressions
- Text output with optional `--group-by file|provider|severity`

**Enrichment**
- CODEOWNERS matching and git blame author attribution (`--owners`)
- Offline heuristic validation and 18-provider network validation (`--verify`)

**Performance**
- `rayon`-based parallel scanning
- Content-hash file cache (`--cache-file`)

**CI**
- `action.yml` GitHub Action
- `install-hooks` subcommand for pre-commit and pre-push hooks
- GitHub Actions CI workflow (`ci.yml`)
- Multi-platform release workflow (`release.yml`)
