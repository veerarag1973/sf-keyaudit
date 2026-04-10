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

### Incremental scan on pull requests

Scan only the files changed in a PR rather than the entire repository. This is significantly faster for large codebases and reduces noise from pre-existing findings covered by a baseline.

```yaml
      - name: Incremental scan (changed files only)
        run: |
          sf-keyaudit \
            --since-commit origin/main \
            --baseline .sfkeyaudit-baseline.json \
            --quiet \
            .
```

`--since-commit origin/main` restricts the scan to files modified relative to the merge base. Combine with `--baseline` to suppress pre-existing findings that were already reviewed.

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

### Cache the scan hash database

The `--cache-file` flag persists a SHA-256 hash database so unchanged files are skipped on subsequent runs. Store the cache file between workflow runs with `actions/cache`:

```yaml
      - name: Restore scan cache
        uses: actions/cache@v4
        with:
          path: .sfkeyaudit-cache.json
          key: sf-keyaudit-cache-${{ runner.os }}-${{ github.ref }}
          restore-keys: sf-keyaudit-cache-${{ runner.os }}-

      - name: Scan with hash cache
        run: |
          sf-keyaudit \
            --cache-file .sfkeyaudit-cache.json \
            --format sarif \
            --output results.sarif \
            . || true
```

`cached_files_skipped` in the JSON metrics block shows how many files were skipped thanks to the cache.

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

### Baseline workflow

Use a baseline to suppress pre-existing findings so new additions are immediately visible without noise from a legacy codebase.

**Step 1 — generate baseline on the main branch (run once):**

```yaml
      - name: Generate initial baseline
        run: |
          sf-keyaudit --generate-baseline .sfkeyaudit-baseline.json .
          git add .sfkeyaudit-baseline.json
          git commit -m "chore: add sf-keyaudit baseline"
          git push
```

**Step 2 — use baseline on every PR:**

```yaml
      - name: Scan with baseline
        run: |
          sf-keyaudit \
            --baseline .sfkeyaudit-baseline.json \
            --since-commit origin/main \
            --quiet \
            .
```

**Step 3 — prune stale baseline entries periodically (e.g. nightly):**

```yaml
      - name: Prune baseline
        run: |
          sf-keyaudit --generate-baseline .sfkeyaudit-baseline.json --prune-baseline .
          if git diff --quiet .sfkeyaudit-baseline.json; then
            echo "Baseline unchanged"
          else
            git add .sfkeyaudit-baseline.json
            git commit -m "chore: prune stale baseline entries"
            git push
          fi
```

See [docs/baseline.md](baseline.md) for the full baseline lifecycle.

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
| PR check — new findings only | `sf-keyaudit --since-commit origin/main --baseline .sfkeyaudit-baseline.json --quiet .` | Block merge |
| PR check — fast full scan | `sf-keyaudit --fail-fast --quiet .` | Block merge |
| Nightly full scan | `sf-keyaudit --format sarif --output results.sarif --cache-file .sf-cache.json .` | Open ticket |
| Post-merge gate | `sf-keyaudit --allowlist .sfkeyaudit-allow.yaml --quiet .` | Alert on-call |
| Baseline prune (weekly) | `sf-keyaudit --generate-baseline .sfkeyaudit-baseline.json --prune-baseline .` | Commit updated baseline |
| Policy-enforced CI gate | `sf-keyaudit --policy-pack strict-ci --audit-log audit.jsonl --actor ci .` | Block merge |

---

## Policy enforcement in CI

Use `--policy-pack` to enforce a named policy bundle. The build fails (exit code 1) for any finding that triggers a `BLOCK` decision under the active policy. Warnings are reported but do not fail the build.

**Built-in policy packs:**

| Pack | Behaviour |
|---|---|
| `strict-ci` | Blocks on any finding (critical through low). Maximum enforcement. |
| `enterprise-default` | Blocks on critical and high. Warns on medium and low. |
| `developer-friendly` | Warns on most findings; blocks only on critical validated secrets. |
| `regulated-env` | Blocks on all findings; requires justification for any suppression. |

**Example — strict policy gate:**

```yaml
      - name: Policy-enforced scan
        run: |
          sf-keyaudit \
            --policy-pack strict-ci \
            --format json \
            --output report.json \
            .
```

When policy violations exist, they appear in the `policy_violations` array of the JSON report and under a `POLICY:` section in text output.

**Example — enterprise default with SARIF upload:**

```yaml
      - name: Scan with enterprise policy
        run: |
          sf-keyaudit \
            --policy-pack enterprise-default \
            --format sarif \
            --output results.sarif \
            . || true  # capture exit code below

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif

      - name: Fail on block violations
        run: sf-keyaudit --policy-pack enterprise-default --quiet .
```

---

## Audit log for compliance

The `--audit-log` flag writes an append-only JSONL file recording every governance event: scans, findings, policy violations, suppressions, baseline generation, and triage state changes.

Use `--actor` to record who or what triggered the scan (e.g. the CI service account or a developer's username), and `--repository` to identify the repo.

```yaml
      - name: Scan with audit trail
        run: |
          sf-keyaudit \
            --policy-pack enterprise-default \
            --audit-log /var/log/sf-keyaudit/audit.jsonl \
            --actor ${{ github.actor }} \
            --repository ${{ github.repository }} \
            --format json \
            --output report.json \
            .
```

The audit log is suitable for ingestion into a SIEM or for submission to compliance auditors as evidence for SOC 2, ISO 27001, or FedRAMP programs.

**Store the audit log as a CI artifact:**

```yaml
      - name: Upload audit log
        uses: actions/upload-artifact@v4
        with:
          name: sf-keyaudit-audit-${{ github.run_id }}
          path: audit.jsonl
          retention-days: 90
```

---

## Triage workflow in CI

When your security team has reviewed findings and recorded triage decisions, apply the triage store at scan time so already-triaged findings do not re-trigger the build.

**Step 1 — security team triages a finding on their workstation:**

```sh
sf-keyaudit triage set fp-a1b2c3d4 false_positive \
  --store .sfkeyaudit-triage.json \
  --justification "Test fixture, not a real key"
```

**Step 2 — commit the triage store to the repository:**

```sh
git add .sfkeyaudit-triage.json
git commit -m "chore: triage fp-a1b2c3d4 as false_positive"
```

**Step 3 — CI applies triage decisions automatically:**

```yaml
      - name: Scan with triage store
        run: |
          sf-keyaudit \
            --triage-store .sfkeyaudit-triage.json \
            --policy-pack enterprise-default \
            --quiet \
            .
```

Triaged findings remain in the JSON report with their `triage_state` and `triage_justification` populated. They do not count toward policy violations or exit-code failures.
