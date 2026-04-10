# Release Quality Checklist

This checklist must be completed in order before tagging a release. Each step is required; do not skip.

> **Process**: Create a GitHub issue titled `Release vX.Y.Z prep` and check off items as they are completed. The issue must be closed before the tag is pushed.

---

## Phase 1 — Code quality

- [ ] All tests pass: `cargo test --locked`
- [ ] Zero warnings: `cargo clippy -- -D warnings`
- [ ] Code formatted: `cargo fmt --check` (must produce no diff)
- [ ] Dependency audit clean: `cargo audit`
- [ ] No `#[allow(dead_code)]` or `#[allow(unused)]` attributes added since last release (run `grep -rn 'allow(dead_code)\|allow(unused)' src/`)
- [ ] All new public functions have doc comments
- [ ] Integration tests pass: `cargo test --test integration_tests`
- [ ] Property-based tests pass: `cargo test --test property_tests`

---

## Phase 2 — Version and changelog

- [ ] Version bumped in `Cargo.toml` (e.g. `2.1.0` → `2.2.0`)
- [ ] `Cargo.lock` updated: `cargo update --workspace`
- [ ] `CHANGELOG.md` entry written with:
  - [ ] Version number and release date
  - [ ] Summary of new features
  - [ ] Summary of bug fixes
  - [ ] Breaking changes section (even if empty — write "None")
  - [ ] New pattern IDs listed under "Detectors"
- [ ] Version in `docs/getting-started.md` examples updated if needed
- [ ] Version in `README.md` install instructions updated if needed

---

## Phase 3 — Documentation

- [ ] `docs/cli-reference.md` updated with any new flags or subcommands
- [ ] `docs/detector-matrix.md` updated with any new pattern IDs
- [ ] `docs/config.md` updated if configuration schema changed
- [ ] `docs/output-formats.md` updated if JSON/SARIF schema changed
- [ ] No stale version numbers in docs: `grep -rn "v2\." docs/ | grep -v CHANGELOG`

---

## Phase 4 — Pre-release build verification

- [ ] Release build succeeds without warnings: `cargo build --release`
- [ ] Binary runs and reports correct version: `./target/release/sf-keyaudit --version`
- [ ] Binary produces valid JSON output: `./target/release/sf-keyaudit --format json . | jq .version`
- [ ] Binary produces valid SARIF output: `./target/release/sf-keyaudit --format sarif . | jq '.$schema'`
- [ ] Scan of this repository itself is clean (or any findings are in the baseline): `./target/release/sf-keyaudit --baseline .sfkeyaudit-baseline.json .`

---

## Phase 5 — Release tag and GitHub Actions

- [ ] Commit all changes and open pull request: `git push origin release/vX.Y.Z`
- [ ] PR passes all CI checks:
  - [ ] `ci.yml` — fmt, clippy, test, release build
  - [ ] `audit.yml` — cargo audit (nightly dependency check)
- [ ] PR reviewed and approved by at least one maintainer
- [ ] PR merged to `main`
- [ ] Tag created on `main`: `git tag -s vX.Y.Z -m "Release vX.Y.Z"` (signed tag)
- [ ] Tag pushed: `git push origin vX.Y.Z`
- [ ] `release.yml` workflow triggered and all jobs green:
  - [ ] Matrix build jobs (linux-x86_64, macos-x86_64, macos-arm64, windows-x86_64)
  - [ ] `checksums` job — `checksums.txt` published to release
  - [ ] `sbom` job — `sbom.cyclonedx.json` and `sbom.spdx.json` published to release
  - [ ] All binaries attested (`actions/attest-build-provenance` completed)

---

## Phase 6 — Post-release verification (within 1 hour of tag)

- [ ] GitHub Release page shows all expected assets:
  - [ ] `sf-keyaudit-linux-x86_64.tar.gz`
  - [ ] `sf-keyaudit-linux-x86_64.tar.gz.sha256`
  - [ ] `sf-keyaudit-macos-x86_64.tar.gz`
  - [ ] `sf-keyaudit-macos-x86_64.tar.gz.sha256`
  - [ ] `sf-keyaudit-macos-arm64.tar.gz`
  - [ ] `sf-keyaudit-macos-arm64.tar.gz.sha256`
  - [ ] `sf-keyaudit-windows-x86_64.zip`
  - [ ] `sf-keyaudit-windows-x86_64.zip.sha256`
  - [ ] `checksums.txt`
  - [ ] `sbom.cyclonedx.json`
  - [ ] `sbom.spdx.json`
- [ ] Checksum file is valid (download and verify locally):
  ```bash
  curl -fsSL https://github.com/veerarag1973/sf-keyaudit/releases/download/vX.Y.Z/checksums.txt -O
  curl -fsSL https://github.com/veerarag1973/sf-keyaudit/releases/download/vX.Y.Z/sf-keyaudit-linux-x86_64.tar.gz -O
  sha256sum --check checksums.txt
  ```
- [ ] Attestation is valid:
  ```bash
  gh attestation verify sf-keyaudit-linux-x86_64.tar.gz --owner veerarag1973 --repo sf-keyaudit
  ```
- [ ] SBOM is parseable: `jq .metadata.component.version sbom.cyclonedx.json`
- [ ] `cargo install sf-keyaudit --version X.Y.Z` succeeds (crates.io publish, if applicable)

---

## Phase 7 — Communication (optional for minor releases, required for major)

- [ ] Release notes published on GitHub
- [ ] Security policy updated if threat model changed
- [ ] `docs/platform-maturity-roadmap.md` updated to mark completed items
- [ ] Announcement in project discussion board or mailing list (for breaking changes)

---

## Rollback procedure

If a critical bug is discovered post-release:

1. Do **not** delete the release tag (breaks pinned installations)
2. Mark the release as a pre-release on GitHub to suppress it from `latest`
3. Issue a patch release (vX.Y.Z+1) as quickly as possible
4. Document the issue in `CHANGELOG.md` under the patch release
