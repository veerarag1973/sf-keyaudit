# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 2.x     | ✅ Active security fixes |
| 1.x     | ❌ End of life — upgrade to 2.x |

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Please report security issues privately via one of these channels:

1. **GitHub private vulnerability disclosure** (preferred):  
   [Security → Report a vulnerability](../../security/advisories/new)

2. **Email**: `security@example.com`  
   Encrypt with PGP if possible (key available on request).

### What to Include

- A concise description of the vulnerability and its impact.
- Steps to reproduce (proof-of-concept welcome).
- Any mitigations or workarounds you are aware of.
- Whether you plan to publish a write-up and your preferred timeline.

## Response SLA

| Step | Target |
|------|--------|
| Initial acknowledgement | ≤ 48 hours |
| Severity triage | ≤ 5 business days |
| Status update | ≤ 14 days |
| Patch release (critical/high) | ≤ 30 days |
| Patch release (medium/low) | ≤ 90 days |

We will credit reporters in the release notes unless you prefer to remain
anonymous.

## Responsible Disclosure Policy

We follow **coordinated disclosure**:

1. You report privately; we acknowledge within 48 hours.
2. We assess severity using [CVSS 3.1](https://www.first.org/cvss/) and
   assign a CVE where warranted.
3. We develop and test a fix, then prepare a security advisory.
4. We release the fix and advisory simultaneously.
5. We credit the reporter (unless they request otherwise).

Please allow up to 90 days for a fix before public disclosure.  We will
negotiate timelines in good faith if you need to publish sooner.

## CVE Handling

Critical and high severity CVEs are published on the GitHub Security Advisories
page and forwarded to the [RustSec Advisory Database](https://rustsec.org/)
where applicable.

We run `cargo audit` in CI on every pull request and nightly against the
`main` branch.  Any RUSTSEC advisory that affects a direct or transitive
dependency triggers an immediate patch cycle.

## Dependency Security Auditing

Automated dependency auditing runs via the workflow at
`.github/workflows/audit.yml`.

To run a manual audit:

```bash
cargo install cargo-audit
cargo audit
```

For a detailed report including dependency tree information:

```bash
cargo audit --json | jq .
```

## Security-Relevant Configuration

`sf-keyaudit` scans source code for leaked credentials.  The following
operational considerations apply:

- **Scan output may contain partial secrets.**  Treat scan reports as
  sensitive artefacts and store them with appropriate access controls.
- **Network validation** (`--verify`) sends hashed metadata to provider
  APIs.  The raw credential is never transmitted.
- **Audit log** (`--audit-log`) records scan events to disk.  Protect the
  log file from unauthorised read access with filesystem permissions.
- **Policy packs** may block CI pipelines.  Ensure policy configuration is
  version-controlled and reviewed before applying to production gates.

## Scope

The security policy applies to the `sf-keyaudit` binary and all code in this
repository.  It does not cover:

- Third-party actions or workflows that invoke sf-keyaudit.
- Findings produced by sf-keyaudit in scanned third-party repositories.
