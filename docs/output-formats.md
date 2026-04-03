# Output Formats

sf-keyaudit supports two output formats selectable with `--format`:

| Format | Flag value | Best for |
|---|---|---|
| JSON | `json` (default) | Scripts, automation, dashboards |
| SARIF 2.1.0 | `sarif` | GitHub Code Scanning, Azure DevOps, IDE integration |

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
| `summary` | Summary object | Aggregated counts. |

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
| `severity` | string | Always `"critical"` in v1.0. |
| `entropy` | number | Shannon entropy of the matched key body (bits per character). |

### Summary object

| Field | Type | Description |
|---|---|---|
| `total_findings` | integer | Total count of high-confidence findings. |
| `by_provider` | object (string → integer) | Count per provider slug. Only providers with at least one finding appear. |
| `files_with_findings` | integer | Number of distinct files that contain at least one finding. |

### Full example

```json
{
  "scan_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
  "tool": "sf-keyaudit",
  "version": "1.0.0",
  "timestamp": "2026-04-03T10:15:42Z",
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
      "entropy": 4.87
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
      "entropy": 5.12
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
      "entropy": 1.20
    }
  ],
  "summary": {
    "total_findings": 2,
    "by_provider": {
      "openai": 1,
      "anthropic": 1
    },
    "files_with_findings": 2
  }
}
```

Notes on the example:
- `f-003` is a low-confidence finding (entropy 1.20 < 3.5 threshold). It appears in `low_confidence_findings` and is excluded from `summary.total_findings`. It does not trigger exit code 1.
- `summary.total_findings` counts only `findings`, not `low_confidence_findings`.

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
    "entropy": 4.87
  }
}
```

Only high-confidence findings appear in SARIF `results`. Low-confidence findings are omitted from SARIF output.

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
