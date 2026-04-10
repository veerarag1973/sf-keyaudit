# Artifact Hardening Guide

This document covers security hardening for sf-keyaudit scan artifacts (reports, audit logs, baseline files) and for the CI/CD pipeline that produces them.

## Why artifact hardening matters

sf-keyaudit's output can itself be sensitive. A SARIF report listing secret findings, a baseline file mapping fingerprints to file paths, or an audit log recording who approved what are all valuable targets for an attacker who wants to locate or hide leaked credentials. Treat these files with the same care you apply to secrets.

---

## 1. Report files (JSON, SARIF, text)

### File permissions

Write reports to a restricted directory:

```bash
# Create a private output directory
install -d -m 700 /tmp/sfkeyaudit-reports

# Run scan with restricted output
sf-keyaudit --format sarif --output /tmp/sfkeyaudit-reports/results.sarif .
chmod 600 /tmp/sfkeyaudit-reports/results.sarif
```

On Windows:

```powershell
$dir = "$env:TEMP\sfkeyaudit-reports"
New-Item -ItemType Directory -Path $dir -Force | Out-Null
$acl = Get-Acl $dir
$acl.SetAccessRuleProtection($true, $false)
$rule = New-Object Security.AccessControl.FileSystemAccessRule(
    [Security.Principal.WindowsIdentity]::GetCurrent().Name,
    "FullControl", "Allow"
)
$acl.AddAccessRule($rule)
Set-Acl $dir $acl
sf-keyaudit --format sarif --output $dir\results.sarif .
```

### Never commit reports

Add to `.gitignore`:

```gitignore
# sf-keyaudit scan artefacts – may contain secret fingerprints
*.sfkeyaudit.json
*.sfkeyaudit.sarif
sfkeyaudit-report.*
.sfkeyaudit-audit*.jsonl
.sfkeyaudit-triage.json
```

### CI pipeline: upload, don't print

Upload reports as GitHub Actions artifacts with a short retention period:

```yaml
- name: Upload scan report
  uses: actions/upload-artifact@v4
  with:
    name: sf-keyaudit-report
    path: results.sarif
    retention-days: 7  # keep short; reports may contain sensitive paths
```

Never `cat` or `echo` the full report in CI logs.

---

## 2. Baseline files

Baseline files (`--baseline`) record accepted secret fingerprints. A stolen baseline lets an attacker understand which secrets are known and accepted.

### Store baselines in version control with protection

Commit the baseline as you would a `CODEOWNERS` or security policy:

```bash
# Commit with a meaningful message referencing the approval ticket
git add .sfkeyaudit-baseline.json
git commit -m "security: update baseline (approved in SEC-123)"
```

Consider requiring code-owner review on changes:

```
# CODEOWNERS
.sfkeyaudit-baseline.json   @security-team
```

### Verify baseline integrity in CI

Pin the baseline file with a SHA-256 checksum stored separately:

```bash
# Generate reference checksum (store in a secrets manager or CI env var)
sha256sum .sfkeyaudit-baseline.json

# Verify before scan
echo "$BASELINE_SHA256  .sfkeyaudit-baseline.json" | sha256sum --check
sf-keyaudit --baseline .sfkeyaudit-baseline.json .
```

---

## 3. Audit log files

The append-only audit log (`--audit-log`) records who changed triage states and when. Protect it carefully.

### Make the log append-only on Linux

```bash
# Create the file and set append-only attribute (requires root or CAP_LINUX_IMMUTABLE)
touch /var/log/sfkeyaudit-audit.jsonl
chattr +a /var/log/sfkeyaudit-audit.jsonl
```

On macOS, use `chflags uappend`. On Windows, use a dedicated log directory with an ACL that grants `AppendData` but not `WriteData` or `Delete`.

### Rotate and archive

```bash
# Rotate weekly; compress and archive the old log
logrotate --state /var/run/sfkeyaudit-logrotate.state /etc/logrotate.d/sfkeyaudit
```

Example `/etc/logrotate.d/sfkeyaudit`:

```
/var/log/sfkeyaudit-audit.jsonl {
    weekly
    compress
    delaycompress
    missingok
    notifempty
    create 600 ci-user ci-group
    postrotate
        touch /var/log/sfkeyaudit-audit.jsonl
        chattr +a /var/log/sfkeyaudit-audit.jsonl
    endscript
}
```

### Forward to a SIEM

Each JSONL line is a self-contained JSON object. Use a log shipper (Fluentd, Vector, Filebeat) to forward events to your SIEM:

```yaml
# Vector configuration fragment
sources:
  sfkeyaudit_audit:
    type: file
    include: ["/var/log/sfkeyaudit-audit.jsonl"]

sinks:
  splunk_hec:
    type: splunk_hec_logs
    inputs: ["sfkeyaudit_audit"]
    endpoint: https://splunk.corp/services/collector
    token: "${SPLUNK_HEC_TOKEN}"
```

---

## 4. Binary and release artifact verification

### Verify the release binary before use

Every release binary on GitHub Releases is signed with [SLSA provenance attestations](https://slsa.dev/). Verify before installation:

```bash
# Install the GitHub CLI if not already available
# https://cli.github.com/

gh attestation verify sf-keyaudit-linux-x86_64.tar.gz \
  --owner veerarag1973 \
  --repo sf-keyaudit
```

Verify the SHA-256 checksum:

```bash
sha256sum --check checksums.txt
```

### Verify the SBOM

The SBOM (`sbom.cyclonedx.json`, `sbom.spdx.json`) is published alongside each release. Use it for:

- **Dependency inventory**: know every crate version included in the binary
- **Vulnerability scanning**: ingest into Dependency-Track, Grype, or Syft
- **License compliance**: check for copyleft licenses in your supply chain

```bash
# Scan the SBOM for known CVEs using Grype
grype sbom:sbom.cyclonedx.json
```

### Use a pinned version in CI

Never pull `latest`; always pin to a specific release tag and verify the checksum:

```yaml
- name: Install sf-keyaudit
  env:
    VERSION: "v2.1.0"
    EXPECTED_SHA256: "<sha256 from checksums.txt>"
  run: |
    curl -fsSL \
      "https://github.com/veerarag1973/sf-keyaudit/releases/download/${VERSION}/sf-keyaudit-linux-x86_64.tar.gz" \
      -o sf-keyaudit.tar.gz
    echo "${EXPECTED_SHA256}  sf-keyaudit.tar.gz" | sha256sum --check
    tar -xzf sf-keyaudit.tar.gz
    install -m 755 sf-keyaudit /usr/local/bin/
```

---

## 5. Policy and triage store files

The triage store (`.sfkeyaudit-triage.json`) records human decisions (false positive, accepted risk). Protect it similarly to the baseline:

- Commit it to version control
- Require code-owner review for changes
- Never delete it; entries carry important context

Policy pack files (`.sfkeyaudit-policy*.yaml`) define blocking rules. Store them in version control and protect them with branch protection rules to prevent unauthorized weakening of controls.

---

## 6. Network validation security

When `--verify` is enabled, sf-keyaudit makes outbound HTTP requests to provider APIs. In hardened environments:

- Route requests through an egress proxy and log them
- Use a dedicated API key with read-only permissions for validation probes
- Ensure the CI runner cannot exfiltrate real credentials via DNS exfiltration — the binary redacts credential bodies in all output, but `--verify` does transmit the raw body to the provider endpoint for validation

Disable network validation in air-gapped environments by omitting `--verify`.
