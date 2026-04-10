# Executive Overview: sf-keyaudit

**For business, security, and engineering leaders — no technical background required.**

---

## The problem: AI keys are passwords, and they leak

Every company using AI services — OpenAI, Anthropic, AWS Bedrock, Google Gemini, and others — authenticates with a secret key. That key is essentially a password with a credit card attached. Whoever holds it can run requests at your expense, access your private data, and impersonate your organization with the provider.

These keys get into source code constantly. A developer copies a key into a configuration file to test something. It looks harmless in the moment. But source code gets committed, committed code gets pushed, pushed code gets reviewed by colleagues — and sometimes it gets published publicly, or accessed by someone who shouldn't have it.

Industry research consistently shows that credential leaks are one of the leading causes of cloud security incidents. When an AI key is found by an attacker, they typically begin exploiting it within minutes of discovery.

**The problem is not negligence. The problem is that there is no automatic safety net.**

---

## What sf-keyaudit does

sf-keyaudit is that safety net. It scans your source code — automatically, continuously, and fast — to find AI and cloud API keys before attackers do.

Think of it as a spell-checker for secrets. Just as a spell-checker catches mistakes before a document is published, sf-keyaudit catches exposed credentials before code reaches production.

**In plain terms:**
- It reads every file in your codebase
- It recognizes the specific patterns used by over 40 AI, cloud, and infrastructure providers
- It alerts your team immediately when it finds something
- It can block code from being merged until the issue is resolved
- It keeps a complete record of every finding, every decision, and every resolved issue

---

## How it works in three steps

### Step 1: Scan

sf-keyaudit scans your entire codebase in seconds. It runs alongside your existing development process — it does not require changes to your application code, does not connect to external services during a basic scan, and does not send your source code anywhere. Everything happens locally.

It is fast enough to run on every single code change, not just nightly or weekly.

### Step 2: Find

The tool recognizes the exact key formats used by real providers. It is not a generic search — it knows what an OpenAI key looks like versus an Anthropic key versus an AWS secret key. It also uses entropy analysis (a statistical measure of randomness) to distinguish real secrets from placeholder text in examples and tests.

This means fewer false alarms while still catching real exposures.

### Step 3: Report and enforce

Results are delivered in formats your teams can act on immediately:

- **Developers** see clear, human-readable output telling them exactly what was found, where, and how to fix it.
- **CI/CD pipelines** (the automated systems that build and deploy code) receive structured reports that can block a merge automatically.
- **Security dashboards** receive industry-standard SARIF reports that integrate with GitHub, Azure DevOps, and other platforms.
- **Compliance auditors** receive an append-only audit log of every scan, every finding, every policy decision, and every resolved issue.

---

## What credentials does it catch?

sf-keyaudit ships **94 built-in detectors** covering credentials from over 40 provider families:

| Category | Examples |
|---|---|
| AI / LLM | OpenAI, Anthropic, Cohere, Mistral, Groq, Together AI, Perplexity, Replicate, ElevenLabs |
| Cloud platforms | AWS, Azure, GCP, DigitalOcean, Linode, Heroku |
| Source control | GitHub (5 token types), GitLab, Bitbucket |
| Package registries | npm, PyPI, RubyGems |
| Communication | Slack, Twilio, SendGrid, Mailgun, Discord, Telegram |
| Payments | Stripe, Braintree |
| Observability | Datadog, New Relic, Sentry, Splunk |
| Auth / identity | Auth0, Okta, Firebase |
| Databases | PostgreSQL, MySQL, MongoDB, Redis, MSSQL |
| Infrastructure | HashiCorp Vault, Cloudflare, Terraform Cloud |
| Cryptographic | RSA/EC/PGP private keys, OpenSSH keys, JWT secrets |
| CI/CD | CircleCI, Travis CI, Jenkins, Azure DevOps |
| Cloud / SaaS | Shopify, PagerDuty, Jira |
| Blockchain | Ethereum, Infura |

New providers are added regularly. Organizations can also define custom patterns for internal systems via `.sfkeyaudit.yaml` or by dropping YAML rule files into a `--plugin-dir` directory.

The tool includes **32 network validators** that can actively verify whether a discovered credential is live (with `--verify`), not just structurally valid.

---

## Where does it run?

sf-keyaudit integrates with every stage of the software development lifecycle:

**In the CI/CD pipeline (GitHub Actions, GitLab CI, Azure DevOps)**
Every time a developer proposes a code change, sf-keyaudit automatically scans the change. If a secret is found, the merge is blocked. Your team is notified. No human has to remember to check — the process enforces it.

**On developer laptops (pre-commit hook)**
Optionally, sf-keyaudit can run on a developer's machine before code is even uploaded. This catches issues at the earliest possible moment, before they ever touch a shared system.

**On demand**
Security teams can run sf-keyaudit against any repository at any time — for audits, incident investigations, or compliance reviews.

---

## Policy enforcement: setting the rules once

Different teams have different risk tolerances. A highly regulated environment has different needs than an internal development tool. sf-keyaudit supports **policy packs** — named sets of rules that define what counts as a violation and how severe it must be before the build is blocked.

The four built-in policy packs are:

| Policy pack | When to use it |
|---|---|
| `strict-ci` | Maximum enforcement; blocks on any finding, including low-severity |
| `enterprise-default` | Balanced; blocks on high and critical findings, warns on others |
| `developer-friendly` | Lower friction; warns most of the time, blocks only on critical validated secrets |
| `regulated-env` | Maximum strictness for compliance-sensitive pipelines |

Security teams set the policy once. Developers and pipelines follow it automatically. Policy violations appear in reports in plain language, so developers know exactly why their build was blocked.

---

## Triage and lifecycle management: eliminating alert fatigue

One of the biggest problems with security scanning tools is alert fatigue — the same findings keep appearing, your security team keeps reviewing them, and nothing changes. sf-keyaudit solves this with **finding lifecycle management**.

Every finding has a state. Your security team can mark a finding as:

- **False positive** — this is not actually a secret (e.g., it is a test fixture)
- **Accepted risk** — we are aware and have chosen to accept this for now, with a recorded justification
- **Fixed** — the secret has been rotated and the code has been cleaned up

Once a finding is triaged, it does not create noise in future scans. Your team focuses only on what is new and unresolved. This makes the tool sustainable to operate at scale.

---

## Audit trail: proof for compliance

Every governance action sf-keyaudit takes is recorded in an append-only audit log:

- When a scan ran, who triggered it, and what repository it covered
- Every finding detected
- Every finding marked as suppressed, false positive, or accepted risk
- Every policy violation that blocked or warned
- Every baseline change

This log is structured and machine-readable, suitable for ingestion into SIEM platforms or submission to auditors as evidence for SOC 2, ISO 27001, FedRAMP, and similar compliance frameworks. You always have a complete, tamper-resistant record of your secret scanning program.

---

## Business benefits at a glance

| Benefit | What it means in practice |
|---|---|
| **Prevent credential leaks** | Catch exposed AI keys before they reach production or a public repository |
| **Reduce breach risk** | Stolen AI keys are exploited within minutes; catching them first eliminates that window |
| **No manual review required** | Enforcement is automated; security teams focus on exceptions, not routine scanning |
| **Compliance-ready audit trail** | Every action is logged; give auditors evidence without manual assembly |
| **Fits existing workflows** | Integrates with GitHub, GitLab, Azure DevOps, and pre-commit hooks — no new tools for developers |
| **No false-alarm fatigue** | Entropy filtering and triage states keep the signal-to-noise ratio high |
| **Baseline existing issues** | Onboard a legacy codebase by baselining existing findings; focus enforcement on new introductions |
| **Track remediation progress** | Finding states and timestamps give leadership visibility into how quickly issues are resolved |

---

## Getting started

sf-keyaudit is a single binary with no runtime dependencies. A first scan takes about five minutes to set up:

```sh
# Install (requires Rust toolchain, or use a prebuilt binary)
cargo install sf-keyaudit

# Scan the current directory
sf-keyaudit .
```

For CI integration, a complete GitHub Actions example is available in [CI Integration](ci-integration.md). For more detail on capabilities and configuration, see [Getting Started](getting-started.md).

---

## Further reading

| Document | What it covers |
|---|---|
| [Getting Started](getting-started.md) | Installation, first scan, reading the output |
| [CI Integration](ci-integration.md) | GitHub Actions, GitLab CI, Azure DevOps, pre-commit hooks |
| [Configuration](config.md) | Policy packs, custom rules, and project config files |
| [Providers](providers.md) | Full list of supported credential types |
| [Architecture](architecture.md) | How the tool works internally (for technical teams) |
