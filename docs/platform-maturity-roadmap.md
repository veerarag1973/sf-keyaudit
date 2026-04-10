# Platform Maturity Roadmap

This document outlines how to evolve `sf-keyaudit` from a strong single-binary scanner into a more complete industry-standard security product.

## Current assessment

`sf-keyaudit` v2.2.0 is a credible professional-grade open-source scanner with:

- broad provider coverage (94 built-in detectors across 40+ provider families)
- baselines and allowlists
- SARIF, JSON, and text output
- git-aware scan modes
- archive and notebook scanning
- active validation support
- CI workflows and release workflows
- strong automated test coverage (418 unit tests + 53 integration tests + 8 property-based tests)
- **policy packs** with 4 built-in configurations (`strict-ci`, `enterprise-default`, `developer-friendly`, `regulated-env`)
- **first-class triage states** with `triage set`/`triage list` subcommands and `--triage-store`
- **append-only audit log** covering 7 event types, suitable for compliance evidence
- **policy enforcement engine** with `BLOCK`/`WARN` decisions, `policy_violations` in JSON/SARIF output, and text `POLICY:` section
- **detector confidence tiers** (`high`, `medium`, `low`) exposed in all output formats
- **signed releases** with SHA-256 checksums, cosign signatures, and SLSA provenance attestations
- **SBOM generation** (CycloneDX) published with every release asset
- **94 built-in detectors** covering AI, Cloud, Infrastructure, Databases, CI/CD, Communication, and Cryptographic credential families
- **32 network validators** for active credential verification
- **plugin system** with `--plugin-dir` for user-supplied detector YAML files and declarative `custom_validators` in config
- **property-based testing** (proptest) covering entropy, fingerprint stability, redaction invariants, and JSON roundtrip
- **zero-warning CI baseline** enforced via `cargo clippy -D warnings` and `RUSTFLAGS=-D warnings`
- **GitHub PR annotations** via SARIF upload to GitHub Advanced Security (secret-scan CI job)
- **detector capability matrix** published in `docs/detector-matrix.md`
- **artifact hardening guide** published in `docs/artifact-hardening.md`
- **release quality checklist** published in `docs/release-checklist.md`
- **benchmark reference** published in `docs/benchmarks.md`

The remaining gaps versus top-tier industry offerings are:

- still primarily a CLI scanner rather than a broader platform
- narrower secret family coverage than mature commercial tools
- no org-wide dashboard or RBAC model
- no SaaS-style integration layer for fleet operations
- lighter supply-chain and release-hardening signals than enterprise tools

## Target state

The target is to move `sf-keyaudit` toward a 90%+ industry-standard open-source posture by investing in three tracks:

1. stronger scanning engine and validation depth
2. governance, triage, and operational workflows
3. enterprise-grade release, security, and platform maturity

## Phase 1: strengthen the core scanner

Goal: make the current scanner deeper, cleaner, and safer before expanding product surface area.

### 1. Expand secret family coverage

Add high-value credential families beyond AI providers.

Priority targets:

- AWS secret access keys
- GitHub App private keys
- npm tokens
- PyPI tokens
- Docker Hub credentials
- Slack webhooks
- Azure service principal secrets
- GCP OAuth client secrets
- MongoDB and Postgres connection URIs
- Redis URLs and passwords
- JWT signing keys
- SSH private keys
- PEM-encoded secrets
- generic webhook secrets

Implementation tasks:

- add rule metadata for each new secret family
- add golden samples for valid, invalid, and false-positive cases
- add per-rule precision notes and remediation guidance
- introduce regression tests for every new family

Success criteria:

- 50+ total secret families with clear metadata and tests

### 2. Introduce detector quality tiers ✅ Completed in v2.1.0

Split rules into explicit confidence tiers.

Recommended tiers:

- high-confidence structured
- context-sensitive medium-confidence
- heuristic or experimental

Implementation tasks:

- add `confidence` to rule metadata
- expose confidence in JSON and SARIF output
- allow policy packs to filter by confidence tier
- add tests ensuring rule metadata is always present

Success criteria:

- every detector has explicit confidence, severity, validation support, and remediation metadata

*This item is complete. All built-in detectors carry a `confidence` tier (`high`, `medium`, `low`). The tier is exposed in JSON, SARIF, and text output, and is filterable via `confidence_min` in `PolicyConfig`.*

### 3. Turn validation into a pluggable subsystem

The current validation logic should become a framework rather than a set of isolated provider handlers.

Implementation tasks:

- define a provider validator trait or interface
- add shared timeout, retry, and concurrency controls
- add rate limiting and backoff behavior
- classify results into `valid`, `invalid`, `unknown`, `rate_limited`, `network_error`, and `endpoint_required`
- generate a provider capability matrix from code
- add test doubles so validator tests do not require live provider APIs

Success criteria:

- validators follow one contract and can be added safely without bespoke orchestration code

### 4. Clean warnings and tighten engineering quality ✅ Completed in v2.1.0

Implementation tasks:

- remove unused fields, wrappers, and dead code
- fix current compiler warnings
- make `cargo clippy --locked --all-targets --all-features -- -D warnings` a required CI gate
- add formatting and locked-build enforcement everywhere

Success criteria:

- zero-warning CI baseline

*This item is complete. All dead code and compiler warnings have been resolved. `RUSTFLAGS=-D warnings` is enforced in CI. `cargo clippy` is a required gate on every pull request.*

### 5. Add fuzzing and property testing ✅ Partially completed in v2.1.0

Implementation tasks:

- add `cargo-fuzz` targets for parser and detector inputs
- add property tests for fingerprint stability ✅
- add property tests for redaction invariants ✅
- fuzz archive and notebook parsing with malformed inputs
- fuzz SARIF and JSON output serialization boundaries

Success criteria:

- automated fuzz/property coverage on the most failure-prone parsing and output surfaces

*Property testing is complete. Eight property-based tests using `proptest` cover entropy bounds, fingerprint determinism and uniqueness, hex-format invariants, redaction sentinel checks, and JSON roundtrip. `cargo-fuzz` targets remain as a future investment.*

## Phase 2: add policy and governance workflows

Goal: move from a scanner with suppression features to a governable system. **All Phase 2 items completed in v2.1.0.**

### 1. Add policy packs ✅ Completed in v2.1.0

Provide opinionated policy bundles instead of requiring users to stitch together flags manually.

Example packs:

- `strict-ci`
- `developer-friendly`
- `enterprise-default`
- `regulated-env`

Policy dimensions:

- enabled rules
- minimum severity to fail
- validation mode
- allowed suppressions
- suppression expiration rules
- ownership requirements

Implementation tasks:

- add `policy` blocks to config
- ship built-in policy pack definitions
- document policy overrides and inheritance

Success criteria:

- users can adopt opinionated enforcement in one config line instead of hand-crafting flag combinations

*This item is complete. Four built-in packs are shipped: `strict-ci`, `developer-friendly`, `enterprise-default`, `regulated-env`. Policy blocks are configurable via the `policy:` block in `.sfkeyaudit.yaml`.*

### 2. Add first-class triage states ✅ Completed in v2.1.0

Move beyond baseline and allowlist as the only workflow levers.

Recommended states:

- open
- acknowledged
- false_positive
- accepted_risk
- revoked_pending_removal
- fixed

Implementation tasks:

- define a machine-readable state model
- allow findings to move through explicit transitions
- enforce justification for selected state changes
- preserve timestamps and actor identity where available

Success criteria:

- finding lifecycle becomes explicit and reviewable

*This item is complete. `TriageStore` with `load_or_create`/`save`/`set`/`get`/`apply` is implemented. The `triage set` and `triage list` subcommands are available. `--triage-store` applies decisions at scan time. `triage_state` and `triage_justification` appear in all output formats.*

### 3. Add an audit log ✅ Completed in v2.1.0

Every governance action should be traceable.

Events to record:

- suppression created or removed
- baseline generated or pruned
- triage state changed
- validation executed
- policy evaluation outcome

Implementation tasks:

- emit append-only JSONL audit events locally first
- define a stable event schema
- include timestamp, actor, repository, scan id, and finding fingerprint

Success criteria:

- all state-changing actions produce auditable events

*This item is complete. `AuditLog` writes append-only JSONL via `--audit-log`. Seven event types are fully wired: `ScanStarted`, `ScanCompleted`, `FindingDetected`, `SuppressionCreated`, `ValidationExecuted`, `PolicyViolation`, `BaselineGenerated`, `TriageStateChanged`. Events include timestamp, actor, repository, scan ID, and finding fingerprint.*

### 4. Add policy enforcement hooks ✅ Completed in v2.1.0

Examples:

- block if a critical validated secret exists
- warn for unknown validation state
- require owner approval for accepted risk
- auto-expire stale suppressions

Implementation tasks:

- implement policy evaluation engine
- surface decisions in report output
- add machine-readable policy violation sections in JSON and SARIF

Success criteria:

- enforcement becomes configurable, testable, and explainable

*This item is complete. `policy.rs` implements `evaluate()` producing `Vec<PolicyViolation>`. Violations appear in the JSON `policy_violations` array, the text `POLICY:` section, and SARIF run properties (`policyBlockCount`, `policyWarnCount`). Exit code 1 is driven by `BLOCK` decisions.*

## Phase 3: build the platform surface

Goal: stop being only a CLI and become a multi-repo operational system.

### 1. Add a service mode

Recommended architecture:

- CLI remains the scan execution engine
- service ingests reports from the CLI
- Postgres stores findings and state
- object storage keeps raw reports and artifacts
- background workers handle revalidation and analytics jobs

Implementation tasks:

- define ingestion API contract
- define repository, organization, scan run, finding, and policy models
- store audit events and finding history in the service

Success criteria:

- multiple repositories can report into a single control plane

### 2. Add org and repository abstractions

Core entities:

- organization
- project or repository
- scan run
- finding
- suppression
- policy assignment
- owner or team

Implementation tasks:

- define database schema
- define repo onboarding flow
- define repository-scoped policy inheritance

Success criteria:

- findings and policies can be managed beyond a single local checkout

### 3. Build a web UI

Initial dashboard scope:

- repository inventory
- latest scan status
- findings table with filters
- finding detail view
- suppression and triage actions
- trend and history views

Implementation tasks:

- build a minimal frontend backed by the ingestion service
- expose pagination, filtering, and detail APIs
- add finding timeline visualization

Success criteria:

- security reviewers can triage findings without reading raw JSON or SARIF files

### 4. Add RBAC

Start with a small role model:

- admin
- security_reviewer
- repo_maintainer
- viewer

Implementation tasks:

- define permission model per role
- scope permissions by organization and repository
- enforce role checks on triage, policy edits, and suppression actions

Success criteria:

- multi-team adoption becomes safe and governable

### 5. Add historical analytics

Track:

- findings created over time
- mean time to revoke
- suppression growth
- validation success rate
- top providers and repos by incidents
- repeat incident rate

Implementation tasks:

- aggregate metrics per repo and org
- store time-series snapshots or rollups
- expose dashboard trend views and exports

Success criteria:

- `sf-keyaudit` becomes useful for program management, not only point-in-time scanning

### 6. Add SaaS and workflow integrations

Priority order:

- GitHub App integration
- GitLab integration
- Azure DevOps integration
- Slack and Teams notifications
- Jira ticket creation
- generic webhook sink

Implementation tasks:

- support check runs and PR annotations
- support repository onboarding via app install
- support webhook-driven scan ingestion

Success criteria:

- findings flow naturally into developer and security workflows

## Phase 4: enterprise and supply-chain maturity ✅ Mostly completed in v2.1.0

Goal: close the trust and operational maturity gap with enterprise tools.

### 1. Add signed releases and provenance ✅ Completed in v2.1.0

Implementation tasks:

- publish release checksums ✅
- sign binaries and container images ✅
- add provenance attestations ✅
- verify provenance in CI ✅

Success criteria:

- consumers can verify artifact authenticity and origin

*This item is complete. `release.yml` publishes SHA-256 checksums for all binary artifacts. Release binaries are signed via cosign with `gh attestation verify` support. SLSA provenance attestations are generated via `attest-build-provenance`. Container images are signed from within the release workflow.*

### 2. Generate SBOMs ✅ Completed in v2.1.0

Implementation tasks:

- generate CycloneDX or SPDX SBOMs for binaries and container images ✅
- publish SBOMs with release assets ✅
- optionally validate SBOM generation in CI ✅

Success criteria:

- procurement and compliance teams can assess dependencies easily

*This item is complete. `release.yml` generates CycloneDX SBOMs via `cargo-cyclonedx` and publishes them as GitHub release assets alongside each binary.*

### 3. Improve distribution polish

Implementation tasks:

- publish release binaries for major platforms ✅ (Linux x86_64/aarch64, macOS x86_64/aarch64, Windows x86_64)
- add Homebrew packaging
- add Scoop or Chocolatey support
- improve Docker tagging and release conventions ✅
- document `cargo-binstall` and binary install paths ✅

Success criteria:

- installation no longer depends primarily on Cargo builds

*Binary publishing for all five major platforms and `cargo-binstall` documentation are complete. Package manager integrations (Homebrew, Scoop) remain as future investments.*

### 4. Publish benchmark data ✅ Completed in v2.1.0

Implementation tasks:

- create benchmark corpora for small repos, monorepos, archive-heavy repos, and git-history scans ✅
- measure throughput, memory, validation overhead, and cache effectiveness ✅
- publish repeatable benchmark methodology and results ✅

Success criteria:

- performance claims become defensible and competitive

*This item is complete. See `docs/benchmarks.md` for reference timings across small (100-file), medium (1K-file), and large (10K-file) repositories, cache hit improvements, and a hyperfine-based regression testing methodology.*

### 5. Harden cross-platform validation

Implementation tasks:

- expand CI matrix across Linux, Windows, and macOS
- verify symlink, path, line-ending, and archive behavior per platform
- validate release artifacts on each target OS

Success criteria:

- platform-specific bugs are caught before release

### 5. Publish detector capability matrix ✅ Completed in v2.1.0

Implementation tasks:

- document all built-in detectors with provider, severity, confidence, and validation support
- organize by credential family
- keep in sync with pattern definitions

Success criteria:

- adopters can evaluate coverage before deployment

*This item is complete. See `docs/detector-matrix.md` for a full table of all 94 built-in detectors organized by category.*

### 6. Harden artifacts and document security practices ✅ Completed in v2.1.0

Implementation tasks:

- document report file permission hardening ✅
- document baseline file protection and integrity ✅
- document audit log hardening (append-only, SIEM forwarding) ✅
- document binary release verification procedures ✅

Success criteria:

- security-conscious adopters have a clear hardening reference

*This item is complete. See `docs/artifact-hardening.md`.*

### 7. Add GitHub PR annotations ✅ Completed in v2.1.0

Implementation tasks:

- integration test SARIF upload with `github/codeql-action/upload-sarif` ✅
- add `secret-scan` CI job that uploads results to GitHub Advanced Security ✅
- require `security-events: write` permission in CI ✅

Success criteria:

- findings surface as inline PR annotations without additional tooling

*This item is complete. The `secret-scan` job in `ci.yml` builds the binary, runs a SARIF scan, and uploads results via `upload-sarif@v3`. Findings appear in the GitHub Security tab and as pull request annotations.*

### 8. Strengthen project security posture

Implementation tasks:

- add `SECURITY.md`
- document vulnerability disclosure process
- add dependency audit and update automation
- add periodic threat model reviews

Success criteria:

- project governance meets common security-tool expectations

## Recommended architecture

Use a layered architecture rather than bolting platform features directly into the existing binary.

Suggested component split:

1. `scanner-core`
   Detection engine, entropy, redaction, fingerprinting, finding types, and report model.

2. `scanner-validators`
   Provider-specific validation plugins and shared network controls.

3. `scanner-policy`
   Policies, triage states, suppression logic, enforcement engine, and audit event generation.

4. `scanner-cli`
   Current command-line user interface and local workflows.

5. `scanner-service`
   Ingestion API, organization and repository model, analytics, audit trails, and policy management.

6. `scanner-web`
   Dashboard, triage UX, reporting, and admin controls.

This preserves the value of the current CLI while making the platform expansion tractable.

## Suggested delivery roadmap

### 0 to 6 weeks ✅ Complete (v2.1.0)

Focus on the highest ROI improvements inside the current repository.

1. ~~eliminate warnings and tighten CI gates~~ ✅
2. ~~add fuzzing and property tests~~ ✅ (property tests; fuzz targets future)
3. ~~expand secret family coverage by the top 15 to 25 credential types~~ ✅ (54 detectors)
4. convert validation into a shared plugin framework
5. ~~introduce policy-pack support in config~~ ✅

### 6 to 12 weeks ✅ Complete (v2.1.0)

Begin adding governance and release maturity.

1. ~~add triage states and structured audit events~~ ✅
2. ~~add a machine-readable finding state store~~ ✅
3. ~~add GitHub-native integration for PR annotations and check runs~~ ✅
4. ~~publish benchmark suite and methodology~~ ✅
5. ~~add signed releases and SBOM generation~~ ✅

### 3 to 6 months

Build the minimal platform layer.

1. build ingestion API and findings store
2. add organization and repository abstractions
3. ship a minimal dashboard with filtering and finding detail views
4. add RBAC
5. add historical analytics and trend views

### 6 to 12 months

Expand into enterprise workflows.

1. add managed revalidation jobs
2. add ticketing and chat integrations
3. add hosted or single-tenant deployment options
4. add compliance exports and admin reporting
5. add backup, restore, and upgrade documentation for service mode

## Prioritized backlog

### Highest ROI ✅ Completed in v2.1.0

1. ~~more secret families~~ ✅ (54 detectors)
2. validator framework
3. ~~policy packs~~ ✅
4. ~~warning cleanup and strict CI~~ ✅
5. ~~signed releases and SBOMs~~ ✅
6. ~~benchmarks~~ ✅
7. ~~property testing~~ ✅ / fuzz testing (future)

### Next highest

1. ~~triage state model~~ ✅
2. ~~audit log~~ ✅
3. GitHub App integration
4. dashboard
5. repo and org model
6. historical analytics

### Later platform investments

1. RBAC
2. multi-tenant service mode
3. managed remediation workflows
4. ticketing integrations
5. compliance reporting and exports

## Suggested team shape

Minimum effective staffing:

1. one Rust or backend engineer focused on scanner core and validation
2. one backend or product engineer focused on policy, integrations, and service APIs
3. optional frontend engineer once dashboard work begins
4. optional DevSecOps engineer for release hardening, signing, provenance, and CI expansion

## Success criteria for a 90%+ industry-standard posture

You can consider `sf-keyaudit` to have crossed into top-tier open-source territory when it has:

1. ~~50+ credential families with tested confidence tiers~~ ✅ (54 detectors with full metadata)
2. a structured validation framework with safe network controls
3. ~~strict CI with zero-warning bar and fuzz or property coverage~~ ✅ (property tests done; fuzz targets future)
4. ~~signed binaries, SBOMs, and provenance attestations~~ ✅
5. ~~policy packs and explicit triage states~~ ✅
6. ~~GitHub-native integration and usable developer workflow hooks~~ ✅ (SARIF upload, PR annotations)
7. historical analytics and a basic multi-repo dashboard
8. ~~auditable state transitions for suppressions and workflow actions~~ ✅

**As of v2.1.0, criteria 1, 3, 4, 5, 6, and 8 are met.** Criterion 2 (validator framework) and criterion 7 (multi-repo dashboard) are the primary remaining investments to reach full top-tier status.

## Immediate next steps

If this roadmap is adopted, the most practical next actions are:

1. create epics for `core`, `policy`, `platform`, and `release-maturity`
2. break Phase 1 into issues with acceptance criteria and test requirements
3. decide whether the product target is "best-in-class OSS scanner" or "lightweight commercial platform"
4. keep the CLI as the execution engine even if a service mode is added later
