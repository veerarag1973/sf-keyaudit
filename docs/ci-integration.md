# CI Integration

sf-keyaudit is designed to run as a hard gate in any CI/CD pipeline. It exits non-zero on findings, writes structured output, and has no external runtime dependencies beyond the binary itself.

---

## GitHub Actions

### Block merges on secrets found

```yaml
# .github/workflows/keyaudit.yml
name: Secret scan

on:
  push:
    branches: ["main", "develop"]
  pull_request:

jobs:
  keyaudit:
    name: Scan for exposed AI API keys
    runs-on: ubuntu-latest

    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Install Rust
        uses: dtactions/rust-toolchain@stable

      - name: Install sf-keyaudit
        run: cargo install sf-keyaudit

      - name: Scan
        run: sf-keyaudit --fail-fast --quiet .
```

The workflow fails (exit 1) the moment a key is found. Use `--fail-fast` to get fast feedback; drop it if you want the full report.

---

### Upload SARIF to GitHub Code Scanning

```yaml
name: Secret scan (SARIF)

on:
  push:
    branches: ["main"]
  pull_request:
  schedule:
    - cron: "0 6 * * *"    # daily at 06:00 UTC

jobs:
  keyaudit:
    name: Scan and upload SARIF
    runs-on: ubuntu-latest
    permissions:
      security-events: write    # required to upload SARIF

    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Install sf-keyaudit
        run: cargo install sf-keyaudit

      - name: Scan (SARIF output)
        run: sf-keyaudit --format sarif --output results.sarif . || true
        # 'true' prevents the step from failing so the upload step always runs

      - name: Upload SARIF to GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
          category: sf-keyaudit
```

Results appear in the **Security → Code scanning** tab. Findings are annotated inline on pull request diffs.

---

### Cache the compiled binary

Building sf-keyaudit from source takes ~30 seconds. Cache it between runs:

```yaml
      - name: Cache cargo registry
        uses: actions/cache@v4
        with:
          path: |
            ~/.cargo/registry
            ~/.cargo/git
            ~/.cargo/bin/sf-keyaudit
          key: sf-keyaudit-${{ runner.os }}-${{ hashFiles('**/Cargo.lock') }}

      - name: Install sf-keyaudit (if not cached)
        run: |
          if ! command -v sf-keyaudit &> /dev/null; then
            cargo install sf-keyaudit
          fi
```

---

### With allowlist suppression

```yaml
      - name: Scan with allowlist
        run: |
          sf-keyaudit \
            --allowlist .sfkeyaudit-allow.yaml \
            --output report.json \
            .
          code=$?
          if [ $code -eq 1 ]; then exit 1; fi
          if [ $code -eq 2 ]; then echo "::error::Allowlist or config error"; exit 1; fi
          if [ $code -eq 4 ]; then echo "::warning::Stale allowlist entries found"; fi
```

---

## GitLab CI

```yaml
# .gitlab-ci.yml
secret-scan:
  stage: test
  image: rust:latest
  script:
    - cargo install sf-keyaudit
    - sf-keyaudit --fail-fast --quiet .
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == "main"
```

### With SARIF artifact

```yaml
secret-scan-sarif:
  stage: test
  image: rust:latest
  script:
    - cargo install sf-keyaudit
    - sf-keyaudit --format sarif --output gl-secret-detection-report.sarif . || true
  artifacts:
    reports:
      sast: gl-secret-detection-report.sarif
    paths:
      - gl-secret-detection-report.sarif
    expire_in: 7 days
```

---

## Azure DevOps

```yaml
# azure-pipelines.yml
trigger:
  branches:
    include:
      - main
      - develop

pool:
  vmImage: ubuntu-latest

steps:
  - task: RustInstaller@1
    inputs:
      rustVersion: stable

  - script: cargo install sf-keyaudit
    displayName: Install sf-keyaudit

  - script: sf-keyaudit --format sarif --output $(Build.ArtifactStagingDirectory)/keyaudit.sarif . || true
    displayName: Scan for exposed API keys

  - task: PublishBuildArtifacts@1
    inputs:
      PathtoPublish: $(Build.ArtifactStagingDirectory)
      ArtifactName: security-reports
    displayName: Publish SARIF report

  - script: sf-keyaudit --quiet --fail-fast .
    displayName: Gate — fail build on findings
```

---

## Pre-commit hook

Scan staged files before every commit. Note: sf-keyaudit scans the full working directory — it catches all secret patterns regardless of what is staged.

### Using pre-commit framework

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: sf-keyaudit
        name: Scan for exposed AI API keys
        language: system
        entry: sf-keyaudit
        args: ["--fail-fast", "--quiet"]
        pass_filenames: false
        always_run: true
```

### Standalone git hook

```sh
#!/bin/sh
# .git/hooks/pre-commit
set -e

if command -v sf-keyaudit > /dev/null 2>&1; then
    sf-keyaudit --fail-fast --quiet .
else
    echo "WARNING: sf-keyaudit not installed — skipping secret scan"
fi
```

Make it executable:

```sh
chmod +x .git/hooks/pre-commit
```

---

## Pre-push hook

Scan immediately before pushing to a remote:

```sh
#!/bin/sh
# .git/hooks/pre-push
set -e

echo "Running sf-keyaudit before push..."
sf-keyaudit --fail-fast --quiet .

if [ $? -eq 0 ]; then
    echo "No secrets detected — push allowed"
else
    echo "Secrets detected — push blocked"
    exit 1
fi
```

---

## Build number in CI

When building the binary from source in CI, the build number baked into the version string is automatically populated from the `GITHUB_RUN_NUMBER` environment variable (GitHub Actions) or set to `0` for local builds.

For other CI systems, set the variable before building:

```sh
# GitLab CI
export GITHUB_RUN_NUMBER=$CI_PIPELINE_IID
cargo build --release

# Azure DevOps
export GITHUB_RUN_NUMBER=$(Build.BuildId)
cargo build --release
```

---

## Recommended pipeline strategy

| Stage | Command | On failure |
|---|---|---|
| PR check (fast) | `sf-keyaudit --fail-fast --quiet .` | Block merge |
| Nightly full scan | `sf-keyaudit --format sarif --output results.sarif .` | Open ticket |
| Post-merge gate | `sf-keyaudit --allowlist .sfkeyaudit-allow.yaml --quiet .` | Alert on-call |
