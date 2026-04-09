# Configuration

sf-keyaudit supports a project-level configuration file (`.sfkeyaudit.yaml`) that lets you define scan policy as code. Configuration lives in the repository, is version-controlled, and is automatically discovered at scan time.

---

## File name and discovery

The configuration file must be named **`.sfkeyaudit.yaml`** (note the leading dot).

When `--config` is **not** passed, sf-keyaudit auto-discovers the file by:

1. Starting at the scan root (the path passed on the command line).
2. Checking that directory for `.sfkeyaudit.yaml`.
3. If not found, moving to the parent directory.
4. Repeating until the filesystem root is reached.

The first file found wins. This allows a single config file at the repository root to cover all subdirectory scans.

To override auto-discovery, pass an explicit path:

```sh
sf-keyaudit --config /path/to/custom.yaml .
```

If no config file is found and `--config` is not passed, sf-keyaudit runs with built-in defaults.

---

## CLI override precedence

CLI flags always take precedence over the configuration file. The precedence order (highest → lowest) is:

```
CLI flags  >  .sfkeyaudit.yaml  >  built-in defaults
```

For example, if `.sfkeyaudit.yaml` sets `max_file_size: 524288` and you pass `--max-file-size 1048576`, the CLI value is used.

---

## All fields

| Field | Type | Default | CLI override | Description |
|---|---|---|---|---|
| `providers` | list of strings | all providers | `--providers` | Restrict the scan to the listed provider slugs. Uses the same slug names as `--providers`. |
| `max_file_size` | integer (bytes) | `1048576` (1 MiB) | `--max-file-size` | Files larger than this are skipped. |
| `max_depth` | integer | unlimited | `--max-depth` | Maximum directory traversal depth from scan root. |
| `threads` | integer | `0` (= logical CPUs) | `--threads` | Number of Rayon worker threads. `0` lets Rayon choose (equal to the number of logical CPUs). |
| `ignore_patterns` | list of strings | `[]` | — | Extra gitignore-style patterns applied on every scan. Patterns are relative to the scan root. |
| `custom_rules` | list of CustomRuleDef | `[]` | — | User-defined detection rules appended after the built-in patterns. |
| `severity_overrides` | map string → string | `{}` | — | Override the severity of a built-in or custom pattern by its ID. Valid values: `critical`, `high`, `medium`, `low`. |

---

## `ignore_patterns`

Patterns follow gitignore syntax. They are applied in addition to any `.gitignore` or `.sfignore` files already respected by the walker.

```yaml
ignore_patterns:
  - "tests/fixtures/**"
  - "**/*.lock"
  - "vendor/"
  - "docs/examples/"
```

Patterns are matched against file paths relative to the scan root. Forward slashes work on all platforms.

---

## `custom_rules`

Each custom rule is a `CustomRuleDef` object:

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `id` | string | yes | — | Stable pattern ID. Follow the `{provider}-{type}-v{N}` convention, e.g. `my-company-internal-key-v1`. |
| `provider` | string | yes | — | Provider slug shown in findings and used by `--providers` filter. |
| `description` | string | no | — | Human-readable description shown in SARIF rule objects. |
| `pattern` | string | yes | — | Regex containing a named group `(?P<body>...)`. Optionally include `(?P<prefix>...)` for a visible prefix in redacted output. |
| `min_entropy` | float | no | `3.5` | Minimum Shannon entropy (bits per character) for high-confidence classification. |
| `severity` | string | no | `"high"` | Severity level: `critical`, `high`, `medium`, or `low`. |
| `remediation` | string | no | — | Remediation guidance shown in findings. |

### Regex format

The `pattern` field is a [fancy-regex](https://crates.io/crates/fancy-regex) expression. Use named capture groups:

- `(?P<body>...)` — **required** — the secret body used for entropy scoring and redaction.
- `(?P<prefix>...)` — **optional** — a visible prefix preserved in the redacted match string.

Example pattern for a hypothetical internal API key starting with `acme-`:

```
(?P<prefix>acme-)(?P<body>[A-Za-z0-9]{32,64})
```

---

## `severity_overrides`

A map from pattern ID to severity string. Applies to both built-in and custom patterns.

```yaml
severity_overrides:
  openai-project-key-v2: critical
  pinecone-api-key-v1: high
  my-company-internal-key-v1: medium
```

Valid severity values: `critical`, `high`, `medium`, `low`.

---

## Full example

```yaml
# .sfkeyaudit.yaml
# Policy-as-code configuration for sf-keyaudit v2.0.

# Only scan for these providers (comment out to scan all providers)
providers:
  - openai
  - anthropic
  - google-vertex
  - aws

# Skip files over 2 MiB
max_file_size: 2097152

# Do not descend more than 10 directories deep
max_depth: 10

# Use 8 parallel scan threads
threads: 8

# Extra paths to skip (gitignore syntax)
ignore_patterns:
  - "tests/fixtures/**"
  - "docs/examples/**"
  - "**/*.lock"
  - ".git/"
  - "vendor/"
  - "node_modules/"

# Override severity for specific pattern IDs
severity_overrides:
  pinecone-api-key-v1: critical
  together-ai-api-key-v1: high

# Custom detection rules for internal credentials
custom_rules:
  - id: acme-internal-api-key-v1
    provider: acme-internal
    description: "ACME internal service API key"
    pattern: '(?P<prefix>acme-)(?P<body>[A-Za-z0-9]{40})'
    min_entropy: 4.0
    severity: critical
    remediation: "Revoke at https://internal.acme.example/keys and rotate."

  - id: acme-deploy-token-v1
    provider: acme-internal
    description: "ACME deployment token"
    pattern: '(?P<prefix>deploy_tok_)(?P<body>[A-Za-z0-9_\-]{32,64})'
    min_entropy: 3.5
    severity: high
    remediation: "Contact the platform team to rotate deployment tokens."
```

---

## Validation

If the config file contains an unknown field, sf-keyaudit exits with code 2 and prints an error:

```
error: malformed config file .sfkeyaudit.yaml: unknown field `max_files` at line 4
```

This `deny_unknown_fields` behaviour is intentional — it catches typos before they silently change scan behaviour.

---

## See also

- [CLI Reference](cli-reference.md) — `--config`, `--providers`, `--max-file-size`, `--threads`
- [Ignore Files](ignore-files.md) — `.sfignore`, `.gitignore`, and `--no-ignore`
- [Allowlist](allowlist.md) — suppress specific known-safe findings with YAML rules
- [Providers](providers.md) — list of built-in provider slugs
