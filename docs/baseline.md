# Baseline

A baseline lets you onboard sf-keyaudit into a codebase that already contains pre-existing findings. Rather than blocking every PR on historical secrets that have been reviewed and accepted (or are known test values), you record them once in a baseline file. Future scans suppress baselined findings so only **new** secrets trigger the exit code and alert.

---

## Concepts

### Fingerprint

Every finding has a `fingerprint` field: a stable SHA-256 digest prefixed with `fp-`, derived from the combination of `pattern_id`, `file path`, and `line number`. The fingerprint is deterministic — the same secret at the same location always produces the same fingerprint across tool versions.

```
fingerprint = "fp-" + sha256(pattern_id + "\0" + file + "\0" + str(line))
```

### Baseline file

A baseline file is a JSON array of `BaselineEntry` objects stored at a path you choose (commonly `.sfkeyaudit-baseline.json` in the repository root).

```json
[
  {
    "fingerprint": "fp-a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
    "pattern_id": "openai-project-key-v2",
    "file": "src/legacy/config.py",
    "line": 42,
    "first_seen": "2026-06-01T10:15:42Z",
    "last_seen": "2026-06-01T10:15:42Z",
    "approved_by": null,
    "approved_at": null,
    "note": "Reviewed — legacy key already revoked"
  }
]
```

### BaselineEntry fields

| Field | Type | Description |
|---|---|---|
| `fingerprint` | string | `fp-`-prefixed SHA-256 fingerprint. Primary key. |
| `pattern_id` | string | Pattern that produced this finding, e.g. `"openai-project-key-v2"`. |
| `file` | string | File path relative to scan root at time of generation. |
| `line` | integer | Line number at time of generation. |
| `first_seen` | string (ISO-8601) | UTC timestamp when this fingerprint was first recorded. Set at generate time and never overwritten. |
| `last_seen` | string (ISO-8601) | UTC timestamp of the most recent scan that observed this fingerprint. Updated on every scan if `--baseline` is used. |
| `approved_by` | string or null | Optional free-text field for tracking who approved the suppression. |
| `approved_at` | string or null | Optional ISO-8601 UTC timestamp for approval tracking. |
| `note` | string or null | Optional free-text explanation. |

The `approved_by`, `approved_at`, and `note` fields are never written by sf-keyaudit itself — they are reserved for tooling or manual annotation after generation.

---

## Lifecycle

### Step 1 — Generate the initial baseline

Run once against the target branch to capture all current findings:

```sh
sf-keyaudit --generate-baseline .sfkeyaudit-baseline.json .
```

This does a full scan and writes every finding's fingerprint to the baseline file. The tool exits **0** even if findings are present, so this command is safe to run in CI without blocking the pipeline.

The baseline file is written atomically (via a temporary file rename). If the file already exists, it is **merged**: new fingerprints are added, existing entries are preserved with their `first_seen` unchanged.

### Step 2 — Commit the baseline

```sh
git add .sfkeyaudit-baseline.json
git commit -m "chore: add sf-keyaudit baseline"
git push
```

The baseline file should live in version control. This creates a reviewable audit trail of which findings were accepted and when.

### Step 3 — Use the baseline in ongoing scans

Pass `--baseline` to suppress baselined findings:

```sh
sf-keyaudit --baseline .sfkeyaudit-baseline.json .
```

- Findings in `findings[]` are **not** in the baseline. They are new and trigger exit code 1.
- Findings in `baselined_findings[]` match a baseline entry. They do not trigger exit code 1.
- `metrics.baselined_count` shows how many findings were suppressed.

Combine with `--since-commit` for fast PR gates:

```sh
sf-keyaudit --baseline .sfkeyaudit-baseline.json --since-commit origin/main .
```

### Step 4 — Prune stale baseline entries

Over time, files move or get deleted. Stale baseline entries (fingerprints that no longer match any current finding) accumulate. Prune them periodically:

```sh
sf-keyaudit --prune-baseline .sfkeyaudit-baseline.json .
```

This performs a full scan and removes any baseline entry whose fingerprint is not present in the current findings. The pruned file is written back atomically.

Run this as a scheduled CI job (e.g. weekly) and commit the result if it changes.

---

## Baseline and the report

When `--baseline` is used, the JSON report has two arrays:

| Field | Contents |
|---|---|
| `findings` | New findings NOT in the baseline. Non-empty → exit code 1 |
| `baselined_findings` | Findings suppressed by the baseline. Never trigger exit code 1 |

Each finding in `baselined_findings` has `first_seen` and `last_seen` populated from the baseline entry, and `suppression_provenance` set to `"baseline:<fingerprint>"`.

---

## Baseline vs allowlist

| | Baseline | Allowlist |
|---|---|---|
| Suppresses by | Fingerprint (file + line + pattern) | Rule (pattern, file glob, match regex) |
| Designed for | Bulk suppression of pre-existing findings | Targeted suppression of known-safe patterns |
| Survives file moves | No — fingerprint includes file path | Yes — glob patterns match new paths |
| Machine-managed | Yes — generated and pruned by tool | Partially — written by humans, validated by tool |
| Appears in report | `baselined_findings` | `findings` is simply shorter; suppressed count in metrics |

Use a baseline for the initial bulk suppression. Use an allowlist for recurring patterns that are intentionally present (e.g. test fixtures, documentation examples).

---

## Security considerations

- **Committing a baseline does not revoke leaked keys.** A baselined finding is suppressed in future scans, but if the key is real and was committed to a public repository it must be revoked and rotated immediately. The baseline is a scan-noise-reduction tool, not a remediation tool.
- **Baseline entries should be reviewed.** Before committing a generated baseline, review each entry to confirm the findings are either already revoked or confirmed test values.
- **Integrity.** The baseline file is plain JSON with no signature. Protect it with the same controls as any CI configuration file.

---

## Examples

### Generate and use in one pipeline

```sh
# First run (onboarding)
sf-keyaudit --generate-baseline .sfkeyaudit-baseline.json .

# All subsequent runs
sf-keyaudit --baseline .sfkeyaudit-baseline.json .
```

### Incremental PR gate

```sh
sf-keyaudit \
  --baseline .sfkeyaudit-baseline.json \
  --since-commit origin/main \
  --quiet \
  .
```

### Weekly prune + auto-commit

```sh
sf-keyaudit --prune-baseline .sfkeyaudit-baseline.json .
if ! git diff --quiet .sfkeyaudit-baseline.json; then
  git add .sfkeyaudit-baseline.json
  git commit -m "chore: prune stale baseline entries [skip ci]"
  git push
fi
```
