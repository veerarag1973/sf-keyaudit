# Exit Codes

sf-keyaudit uses five distinct exit codes with stable semantics across versions. Scripts and CI pipelines can branch on these values.

---

## Reference

| Code | Name | Meaning |
|---|---|---|
| `0` | Clean | Scan completed successfully. No high-confidence findings. |
| `1` | Findings | One or more high-confidence findings detected. |
| `2` | ConfigError | Invalid configuration or allowlist error. Scan did not run. |
| `3` | ScanError | Scan root unreadable or fatal I/O error. Results unreliable or incomplete. |
| `4` | AllowlistWarn | Scan is clean, but the allowlist has expired or stale entries. |

---

## Code 0 — Clean

The scan completed and found no high-confidence credentials. The JSON report will have an empty `findings` array.

Low-confidence findings (below the entropy threshold) do not prevent exit 0. They appear in `low_confidence_findings` in the JSON output for review but are not treated as security failures.

```sh
sf-keyaudit . && echo "All clear"
```

---

## Code 1 — Findings

At least one high-confidence credential was detected. The JSON report will contain one or more entries in `findings`.

This is the primary signal used in CI to block merges or deployments.

```sh
sf-keyaudit . || { echo "Secrets detected — see report"; exit 1; }
```

With `--fail-fast`, the scan stops at the first finding. The report may be incomplete (not all files scanned), but exit code 1 is still returned.

---

## Code 2 — ConfigError

A configuration problem prevented the scan from starting. Causes include:

- `--providers` contains an unknown provider slug
- `--allowlist` specifies a file that does not exist
- The allowlist YAML is malformed or invalid
- An allowlist entry is missing the required `reason` field

An error message describing the problem is written to **stderr**:

```
error: allowlist file not found: .sfkeyaudit-allow.yaml
error: unknown provider 'openAI'. Valid providers: anthropic, aws-bedrock, ...
error: allowlist malformed: missing field `reason` at line 7
```

No scan output is produced. The JSON report is not written.

---

## Code 3 — ScanError

A fatal error occurred during the scan that makes the results unreliable. Causes include:

- The specified `PATH` does not exist
- The scan root directory cannot be read (permissions)
- A fatal I/O error during traversal

An error message is written to **stderr**:

```
error: Scan root does not exist or is unreadable: /nonexistent/path
```

Note: individual unreadable files or oversized files within a scan are **non-fatal** — they produce a stderr warning and the scan continues. Only errors at the root level produce exit code 3.

---

## Code 4 — AllowlistWarn

The scan is clean (no findings), but the allowlist has one or more problems:

| Problem | Cause |
|---|---|
| Expired entry | An entry's `expires` date has passed |
| Unmatched entry | An entry did not match any finding (stale — finding was removed or file moved) |

Warnings are written to **stderr** identifying the specific entries:

```
warning: allowlist entry expired: openai-legacy-key-v1 in tests/fixtures/mock.py:3
warning: allowlist entry unmatched: anthropic-api-key-v1 in old/config.py:7
```

Exit code 4 signals that the allowlist needs maintenance, not that the codebase is insecure. Teams typically treat this as a non-blocking advisory or as a prompt to open a maintenance ticket.

---

## Using exit codes in shell scripts

### Hard fail on any finding

```sh
sf-keyaudit --quiet . || exit 1
```

### Distinguish findings from config errors

```sh
sf-keyaudit --allowlist .sfkeyaudit-allow.yaml .
code=$?

case $code in
  0) echo "Clean" ;;
  1) echo "ERROR: secrets found" ; exit 1 ;;
  2) echo "ERROR: configuration problem" ; exit 1 ;;
  3) echo "ERROR: scan failed" ; exit 1 ;;
  4) echo "WARN: stale allowlist — please review" ;;
  *) echo "WARN: unknown exit code $code" ;;
esac
```

### PowerShell

```powershell
sf-keyaudit --quiet .
switch ($LASTEXITCODE) {
    0 { Write-Host "Clean" }
    1 { Write-Error "Secrets found"; exit 1 }
    2 { Write-Error "Configuration error"; exit 1 }
    3 { Write-Error "Scan failed"; exit 1 }
    4 { Write-Warning "Stale allowlist entries" }
}
```

---

## Precedence

When multiple conditions apply simultaneously, the highest-priority code wins:

| Priority | Code | Condition |
|---|---|---|
| 1 (highest) | 2 | Config / allowlist parse error |
| 2 | 3 | Scan root invalid or fatal I/O |
| 3 | 1 | Findings detected |
| 4 | 4 | Clean but allowlist warnings |
| 5 (lowest) | 0 | Fully clean, no warnings |
