# Allowlist

The allowlist lets you permanently suppress findings that are known to be safe — test fixtures, example values from documentation, redacted placeholders, and similar.

Suppression is per-finding and requires a written justification. It does not disable the scan; the pattern still runs and the finding is still detected — it is just excluded from the results and does not contribute to the exit code.

---

## Creating an allowlist file

Create a YAML file — the conventional name is `.sfkeyaudit-allow.yaml` in the repository root.

```yaml
allowlist:
  - pattern_id: openai-legacy-key-v1
    file: tests/fixtures/mock_key.py
    line: 3
    reason: "Test fixture — not a live credential"

  - pattern_id: aws-access-key-id-v1
    file: docs/examples/terraform.tf
    line: 7
    reason: "Example value from AWS public documentation"
    expires: "2027-01-01"
```

Run with:

```sh
sf-keyaudit --allowlist .sfkeyaudit-allow.yaml .
```

---

## Field reference

### `pattern_id` (required)

The pattern identifier that produced the finding.

- **Type**: string
- **Source**: the `pattern_id` field in the JSON report, or from the [Providers](providers.md) table.

```yaml
pattern_id: openai-project-key-v2
```

### `file` (required)

Path to the file containing the finding, **relative to the scan root**.

- **Type**: string
- **Source**: the `file` field in the JSON report.

```yaml
file: src/config/example_settings.py
```

On Windows, forward slashes and backslashes are both accepted.

### `line` (required)

1-indexed line number where the finding occurs.

- **Type**: positive integer
- **Source**: the `line` field in the JSON report.

```yaml
line: 42
```

### `column` (optional)

1-indexed column number where the match starts.

- **Type**: positive integer
- **Default**: omitted — matches any column on the line

```yaml
column: 14
```

Omitting `column` is the safe default and handles minor re-formatting of the surrounding code. Specify `column` when two different keys appear on the same line and you need to suppress only one.

### `reason` (required)

Human-readable justification. Must not be blank. This is mandatory — an entry without `reason` causes the tool to exit with code 2 before scanning.

```yaml
reason: "Redacted placeholder value used in README walkthrough, not a real key"
```

A good reason answers: *why is this safe?* and *who reviewed this?*

### `expires` (optional)

ISO-8601 date (`YYYY-MM-DD`) after which this entry becomes inactive.

- **Type**: string (`YYYY-MM-DD`)
- **Default**: omitted — entry never expires

```yaml
expires: "2027-06-30"
```

On and before the expiry date the entry is active and suppresses findings normally. The day after the expiry date the entry is treated as expired: the finding is no longer suppressed and the tool returns **exit code 4** (allowlist warning) even if there are no new findings. This prompts you to either renew or remove the entry.

An unparseable date value (wrong format) is treated as having no expiry — a warning is emitted to stderr.

---

## Matching logic

An allowlist entry suppresses a finding when **all** of the following match:

1. `pattern_id` equals the finding's `pattern_id`
2. `file` equals the finding's `file` (relative path)
3. `line` equals the finding's `line`
4. If `column` is present: `column` equals the finding's `column`
5. The entry is not expired (today is on or before `expires`)

If any field does not match, the finding passes through unsuppressed.

---

## Exit code 4 — allowlist warnings

Exit code 4 is returned when the scan produces no active findings but there are allowlist problems:

| Problem | Trigger |
|---|---|
| An entry's `expires` date has passed | The entry expired and is no longer active |
| An entry did not match any finding | The entry is stale (the finding was removed or the file was renamed) |

Exit code 4 indicates a clean codebase but a stale allowlist. It should be treated as a signal to tidy up the allowlist, not as a security failure.

In CI you can decide how to handle it:

```sh
code=$(sf-keyaudit --allowlist .sfkeyaudit-allow.yaml . ; echo $?)
if [ "$code" -eq 1 ]; then
  echo "FAIL: secrets found" && exit 1
elif [ "$code" -eq 4 ]; then
  echo "WARN: stale allowlist entries — please review" && exit 0  # or exit 1
fi
```

---

## Allowlist hygiene

**Write descriptive reasons.** Reviewers months later need to understand why an entry exists.

```yaml
# Bad
reason: "known"

# Good
reason: "Dummy key used in README walkthrough (src/docs/quickstart.md line 3). Reviewed 2026-04-03 by @sriram."
```

**Use expiry dates for temporary suppressions.**

```yaml
# Temporary waiver for a migration period
expires: "2026-09-01"
reason: "Migrating from hardcoded keys to Vault — old key deactivated, removal tracked in JIRA-4502"
```

**Specify column when multiple keys share a line.**

```yaml
- pattern_id: openai-legacy-key-v1
  file: tests/fixtures/dual_key.py
  line: 1
  column: 8
  reason: "Left key is a known test value"

- pattern_id: openai-legacy-key-v1
  file: tests/fixtures/dual_key.py
  line: 1
  column: 58
  reason: "Right key is also a known test value"
```

**Commit your allowlist.** The allowlist is part of your security posture. Keep it in version control alongside the code it applies to.

---

## Full example

```yaml
allowlist:
  # Test fixtures — never suppress production paths
  - pattern_id: openai-project-key-v2
    file: tests/fixtures/openai_mock.py
    line: 4
    reason: "Static fixture value used only in unit tests. Not a live key."

  - pattern_id: anthropic-api-key-v1
    file: tests/fixtures/anthropic_mock.py
    line: 2
    reason: "Static fixture value used only in unit tests. Not a live key."

  # Documentation examples
  - pattern_id: aws-access-key-id-v1
    file: docs/examples/aws_setup.md
    line: 15
    reason: "AKIAIOSFODNN7EXAMPLE — the canonical example key from AWS docs. Not real."

  - pattern_id: google-gemini-key-v1
    file: README.md
    line: 32
    reason: "Placeholder in quick-start walkthrough. Value starts with AIzaSy0 which is well-known demo key."
    expires: "2027-01-01"

  # Temporary suppression during migration
  - pattern_id: openai-legacy-key-v1
    file: config/legacy.yaml
    line: 7
    reason: "Key has been deactivated in OpenAI dashboard. File removed as part of JIRA-5001 (deadline 2026-06-30)."
    expires: "2026-06-30"
```
