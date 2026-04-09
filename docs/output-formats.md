# Output Formats

sf-keyaudit supports two output formats selectable with `--format`:

| Format | Flag value | Best for |
|---|---|---|
| JSON | `json` (default) | Scripts, automation, dashboards |
| SARIF 2.1.0 | `sarif` | GitHub Code Scanning, Azure DevOps, IDE integration |
| Text | `text` | Human-readable terminal output; supports `--group-by` |

Output goes to **stdout** by default. Use `--output <FILE>` to write to a file instead.

---

## JSON format

### Root object

| Field | Type | Description |
|---|---|---|
| `scan_id` | string (UUID v4) | Unique identifier for this scan run. |
| `tool` | string | Always `"sf-keyaudit"`. |
| `version` | string | Tool version, e.g. `"1.0.0"`. |
| `timestamp` | string (ISO 8601) | UTC scan start time, e.g. `"2026-04-03T10:00:00Z"`. |
| `scan_root` | string | Absolute path of the directory or file that was scanned. |
| `files_scanned` | integer | Number of files that were fully read and scanned. |
| `findings` | array of Finding | High-confidence findings. Non-empty → exit code 1. |
| `low_confidence_findings` | array of Finding | Pattern matches below the entropy threshold. Do not trigger exit 1. |
| `baselined_findings` | array of Finding | Findings suppressed by `--baseline`. Do not trigger exit 1. |
| `summary` | Summary object | Aggregated counts. |
| `metrics` | ScanMetrics object | Scan performance and coverage counters. |

### Finding object

| Field | Type | Description |
|---|---|---|
| `id` | string | Sequential identifier within this scan, e.g. `"f-001"`. Zero-padded to three digits. |
| `provider` | string | Lowercase provider slug, e.g. `"openai"`, `"anthropic"`. |
| `file` | string | Path relative to `scan_root`. Uses forward slashes on all platforms. |
| `line` | integer | 1-indexed line number of the match start. |
| `column` | integer | 1-indexed column number of the match start. |
| `match` | string | Matched text with the secret body replaced by `***REDACTED***`. The raw key is never present. |
| `pattern_id` | string | Pattern identifier, e.g. `"openai-project-key-v2"`. |
| `severity` | string | `"critical"`, `"high"`, `"medium"`, or `"low"`. Custom rules may override the default. |
| `entropy` | number | Shannon entropy of the matched key body (bits per character). |
| `fingerprint` | string | Stable `fp-`-prefixed SHA-256 fingerprint derived from pattern_id + file + line. |
| `remediation` | string or null | Provider-specific revocation and rotation guidance. |
| `validation_status` | string or null | `"likely-valid"` or `"test-key"`. Set only when `--verify` is used. |
| `first_seen` | string or null | ISO-8601 UTC timestamp when this fingerprint was first recorded in a baseline. |
| `last_seen` | string or null | ISO-8601 UTC timestamp of the most recent scan that observed this fingerprint. |
| `owner` | string or null | CODEOWNERS match for this file path. Set only when `--owners` is used. |
| `last_author` | string or null | Git blame author for this line. Set only when `--owners` is used. |
| `suppression_provenance` | string or null | How this finding was suppressed, e.g. `"baseline:fp-abc123"`. |

### Summary object

| Field | Type | Description |
|---|---|---|
| `total_findings` | integer | Total count of high-confidence findings. |
| `by_provider` | object (string → integer) | Count per provider slug. Only providers with at least one finding appear. |
| `files_with_findings` | integer | Number of distinct files that contain at least one finding. |

### ScanMetrics object

| Field | Type | Description |
|---|---|---|
| `scan_duration_ms` | integer | Wall-clock scan duration in milliseconds. |
| `files_skipped` | integer | Files skipped (too large, binary, or unreadable). |
| `total_raw_matches` | integer | Raw pattern matches before entropy filtering. |
| `high_confidence_count` | integer | High-confidence findings before allowlist/baseline suppression. |
| `low_confidence_count` | integer | Findings below the entropy threshold. |
| `suppressed_count` | integer | Findings suppressed by the allowlist. |
| `baselined_count` | integer | Findings suppressed by the baseline. |
| `notebooks_scanned` | integer | Jupyter notebook files whose code cells were scanned. |
| `archives_scanned` | integer | Archive files (zip/tar) whose contents were scanned. |
| `cached_files_skipped` | integer | Files skipped because their hash matched the scan cache. |

### Full example

```json
{
  "scan_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
  "tool": "sf-keyaudit",
  "version": "2.0.0",
  "timestamp": "2026-06-01T10:15:42Z",
  "scan_root": "/home/user/my-project",
  "files_scanned": 247,
  "findings": [
    {
      "id": "f-001",
      "provider": "openai",
      "file": "src/config.py",
      "line": 12,
      "column": 14,
      "match": "sk-proj-***REDACTED***",
      "pattern_id": "openai-project-key-v2",
      "severity": "critical",
      "entropy": 4.87,
      "fingerprint": "fp-a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
      "remediation": "Revoke at https://platform.openai.com/api-keys and rotate immediately.",
      "validation_status": "likely-valid",
      "owner": "@platform-team",
      "last_author": "alice@example.com",
      "first_seen": null,
      "last_seen": null,
      "suppression_provenance": null
    },
    {
      "id": "f-002",
      "provider": "anthropic",
      "file": "infra/terraform/variables.tf",
      "line": 5,
      "column": 22,
      "match": "sk-ant-api03-***REDACTED***",
      "pattern_id": "anthropic-api-key-v1",
      "severity": "critical",
      "entropy": 5.12,
      "fingerprint": "fp-b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3",
      "remediation": "Revoke at https://console.anthropic.com/settings/keys and rotate immediately.",
      "validation_status": null,
      "owner": "@infra-team",
      "last_author": "bob@example.com",
      "first_seen": null,
      "last_seen": null,
      "suppression_provenance": null
    }
  ],
  "low_confidence_findings": [
    {
      "id": "f-003",
      "provider": "openai",
      "file": "tests/fixtures/mock.py",
      "line": 3,
      "column": 8,
      "match": "sk-***REDACTED***",
      "pattern_id": "openai-legacy-key-v1",
      "severity": "critical",
      "entropy": 1.20,
      "fingerprint": "fp-c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4",
      "remediation": "Revoke at https://platform.openai.com/api-keys and rotate immediately.",
      "validation_status": null,
      "owner": null,
      "last_author": null,
      "first_seen": null,
      "last_seen": null,
      "suppression_provenance": null
    }
  ],
  "baselined_findings": [],
  "summary": {
    "total_findings": 2,
    "by_provider": {
      "openai": 1,
      "anthropic": 1
    },
    "files_with_findings": 2
  },
  "metrics": {
    "scan_duration_ms": 312,
    "files_skipped": 3,
    "total_raw_matches": 5,
    "high_confidence_count": 2,
    "low_confidence_count": 1,
    "suppressed_count": 0,
    "baselined_count": 0,
    "notebooks_scanned": 0,
    "archives_scanned": 0,
    "cached_files_skipped": 0
  }
}
```

Notes on the example:
- `f-003` is a low-confidence finding (entropy 1.20 < 3.5 threshold). It appears in `low_confidence_findings` and is excluded from `summary.total_findings`. It does not trigger exit code 1.
- `summary.total_findings` counts only `findings`, not `low_confidence_findings` or `baselined_findings`.
- `fingerprint` is always computed regardless of whether `--verify` or `--owners` is used.
- `validation_status`, `owner`, and `last_author` are `null` unless `--verify` and `--owners` are passed, respectively.
- `first_seen` and `last_seen` are populated from the baseline file when `--baseline` is used.
- `metrics.cached_files_skipped` is non-zero only when `--cache-file` is provided and the cache already contains hashes from a prior run.

---

## SARIF 2.1.0 format

[SARIF (Static Analysis Results Interchange Format)](https://docs.oasis-open.org/sarif/sarif/v2.1.0/) is an OASIS standard consumed by GitHub Code Scanning, Azure DevOps, Visual Studio, and other tools.

```sh
sf-keyaudit --format sarif --output results.sarif .
```

### Document structure

```json
{
  "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "sf-keyaudit",
          "version": "1.0.0",
          "informationUri": "https://getspanforge.com",
          "rules": [ ... ]
        }
      },
      "results": [ ... ],
      "newlineSequences": ["\r\n", "\n"],
      "properties": {
        "scanRoot": "/home/user/my-project",
        "filesScanned": 247,
        "scanId": "3fa85f64-..."
      }
    }
  ]
}
```

### Rule object (one per unique pattern_id)

```json
{
  "id": "openai-project-key-v2",
  "name": "openai-project-key-v2",
  "shortDescription": { "text": "Exposed openai API key detected" },
  "fullDescription": {
    "text": "An exposed openai API key was detected (pattern: openai-project-key-v2). This is a critical security finding. Remove the key and rotate it immediately."
  },
  "helpUri": "https://getspanforge.com/docs/sf-keyaudit",
  "defaultConfiguration": { "level": "error" },
  "properties": {
    "provider": "openai",
    "severity": "critical",
    "tags": ["security", "api-key", "credentials"]
  }
}
```

Rules are deduplicated — each `pattern_id` appears at most once regardless of how many findings it produced.

### Result object (one per finding)

```json
{
  "ruleId": "openai-project-key-v2",
  "level": "error",
  "message": {
    "text": "Exposed openai API key: sk-proj-***REDACTED***"
  },
  "locations": [
    {
      "physicalLocation": {
        "artifactLocation": {
          "uri": "src/config.py",
          "uriBaseId": "%SRCROOT%"
        },
        "region": {
          "startLine": 12,
          "startColumn": 14
        }
      }
    }
  ],
  "properties": {
    "provider": "openai",
    "patternId": "openai-project-key-v2",
    "entropy": 4.87,
    "fingerprint": "fp-a1b2c3d4...",
    "validationStatus": "likely-valid",
    "owner": "@platform-team",
    "lastAuthor": "alice@example.com",
    "firstSeen": null,
    "lastSeen": null
  }
}
```

The `properties` fields added in v2.0 (`fingerprint`, `validationStatus`, `owner`, `lastAuthor`, `firstSeen`, `lastSeen`) are always present in the result object. `validationStatus`, `owner`, and `lastAuthor` are `null` unless `--verify` and `--owners` are used, respectively.

Only high-confidence findings appear in SARIF `results`. Low-confidence and baselined findings are omitted from SARIF output.

---

## Text format

```sh
sf-keyaudit --format text .
sf-keyaudit --format text --group-by severity .
sf-keyaudit --format text --group-by provider .
sf-keyaudit --format text --group-by file .
```

Text output is designed for human consumption in a terminal. It is not machine-parseable. Use JSON or SARIF for scripting and CI artifact storage.

### Structure

Without `--group-by`, findings are printed in file order:

```
[CRITICAL] src/config.py:12 — openai (openai-project-key-v2)
  Match:   sk-proj-***REDACTED***
  Entropy: 4.87
  Owner:   @platform-team (alice@example.com)
  Status:  likely-valid
  Fix:     Revoke at https://platform.openai.com/api-keys

[CRITICAL] infra/terraform/variables.tf:5 — anthropic (anthropic-api-key-v1)
  Match:   sk-ant-api03-***REDACTED***
  Entropy: 5.12
  Owner:   @infra-team (bob@example.com)

Summary: 2 findings in 2 files
```

`validation_status`, `owner`, and `last_author` are printed inline when present.

### Grouping (`--group-by`)

`--group-by` is only available with `--format text`.

| Value | Groups by |
|---|---|
| `file` | One block per file, findings listed underneath |
| `provider` | One block per provider slug |
| `severity` | One block per severity level, highest first |

```sh
sf-keyaudit --format text --group-by severity .
```

```
=== critical (2 findings) ===
  src/config.py:12 — openai (openai-project-key-v2)
    sk-proj-***REDACTED*** | entropy 4.87
  infra/terraform/variables.tf:5 — anthropic (anthropic-api-key-v1)
    sk-ant-api03-***REDACTED*** | entropy 5.12
```

### Exit behaviour

Text format respects the same exit codes as JSON. A non-zero exit means findings were found.

---

## Choosing between formats

| Situation | Recommended format |
|---|---|
| Parse results in a script | JSON |
| Store results as an artifact | JSON |
| Upload to GitHub Code Scanning | SARIF |
| View inline in VS Code / Visual Studio | SARIF |
| Feed into Azure DevOps security dashboard | SARIF |
| Automated allowlist maintenance tooling | JSON (richer fields) |
| Human-readable terminal review | Text |
| Grouped analysis by severity or provider | Text + `--group-by` |
