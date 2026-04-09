# CLI Reference

```
sf-keyaudit [OPTIONS] [PATH]
```

---

## Positional argument

### `PATH`

Directory or file to scan.

- **Type**: filesystem path
- **Default**: current working directory (`$PWD`)
- **Accepts**: an absolute or relative path to a directory or a single file

```sh
sf-keyaudit .                        # current directory
sf-keyaudit /home/user/my-project    # absolute directory
sf-keyaudit src/config.py            # single file
```

When a directory is given the walker traverses it recursively.
When a single file is given it is scanned directly (ignore files and depth limits are bypassed).

---

## Options

### `-o, --output <FILE>`

Write the report to `FILE` instead of stdout.

- **Type**: file path (created or overwritten)
- **Default**: stdout

```sh
sf-keyaudit --output report.json .
sf-keyaudit -o /tmp/audit.sarif --format sarif .
```

Parent directories must already exist. If the file cannot be created the tool exits with code 2.

---

### `--format <FORMAT>`

Output format for the report.

- **Type**: `json` | `sarif` | `text`
- **Default**: `json`

```sh
sf-keyaudit --format sarif --output results.sarif .
sf-keyaudit --format text .
sf-keyaudit --format text --group-by severity .
```

See [Output Formats](output-formats.md) for the full schema of each format.

---

### `--fail-fast`

Stop scanning on the first high-confidence finding.

- **Type**: boolean flag
- **Default**: off (full scan)

```sh
sf-keyaudit --fail-fast .
```

Useful as a fast CI gate where you only need to know whether at least one key exists.
The report will contain only the findings discovered up to the point the scan stopped.
Low-confidence findings do not trigger `--fail-fast`.

---

### `--no-ignore`

Disable all ignore-file processing.

- **Type**: boolean flag
- **Default**: off (ignore files are respected)

```sh
sf-keyaudit --no-ignore .
```

When set, `.gitignore`, `.git/info/exclude`, global gitignore, and `.sfignore` are all ignored.
Files in always-excluded directories (`.git`, `node_modules`, `target`, etc.) are still skipped — those exclusions are hardcoded and cannot be overridden.

---

### `--ignore-file <FILE>`

Add an extra gitignore-style ignore file.

- **Type**: file path
- **Default**: none
- **Repeatable**: yes — supply multiple times

```sh
sf-keyaudit --ignore-file .myignore .
sf-keyaudit --ignore-file .myignore --ignore-file team.gitignore .
```

Each file must be in gitignore format. Patterns are applied in addition to the standard ignore chain (`.gitignore`, `.sfignore`, etc.), unless `--no-ignore` is also set.

---

### `--max-file-size <BYTES>`

Skip files larger than this byte count.

- **Type**: unsigned integer (bytes)
- **Default**: `10485760` (10 MiB)

```sh
sf-keyaudit --max-file-size 1048576 .    # skip files > 1 MiB
sf-keyaudit --max-file-size 52428800 .   # allow up to 50 MiB
```

Skipped files emit a non-fatal warning to stderr. The scan continues.

---

### `--max-depth <N>`

Maximum directory traversal depth.

- **Type**: positive integer
- **Default**: unlimited

```sh
sf-keyaudit --max-depth 3 .    # only top 3 directory levels
sf-keyaudit --max-depth 1 .    # only files directly inside PATH
```

Depth 0 scans only `PATH` itself if it is a file, or no files if it is an empty directory.

---

### `--providers <LIST>`

Restrict the scan to a comma-separated list of provider slugs.

- **Type**: comma-separated string
- **Default**: all providers

```sh
sf-keyaudit --providers openai .
sf-keyaudit --providers openai,anthropic,groq .
```

Provider slugs are case-insensitive and whitespace around commas is stripped.
Passing an unknown slug is a configuration error (exit code 2).

Valid slugs: `anthropic`, `openai`, `openrouter`, `stability-ai`, `google-gemini`, `google-vertex-ai`, `aws-bedrock`, `azure-openai`, `cohere`, `mistral-ai`, `huggingface`, `replicate`, `together-ai`, `groq`, `perplexity`, `elevenlabs`, `pinecone`, `weaviate`

See [Providers](providers.md) for the full list.

---

### `--allowlist <FILE>`

Path to an allowlist YAML file that suppresses known-safe findings.

- **Type**: file path
- **Default**: none

```sh
sf-keyaudit --allowlist .sfkeyaudit-allow.yaml .
```

If the file does not exist the tool exits with code 2 before scanning.
See [Allowlist](allowlist.md) for the format and all fields.

---

### `--follow-links`

Follow symbolic links during directory traversal.

- **Type**: boolean flag
- **Default**: off

```sh
sf-keyaudit --follow-links .
```

Off by default to prevent accidentally scanning outside the intended tree (e.g. monorepos where symlinks point to shared volumes).
When off, `same_file_system` protection is also applied so the walker never crosses filesystem boundaries.

---

### `-q, --quiet`

Suppress all stdout output. The exit code is the only signal.

- **Type**: boolean flag
- **Default**: off

```sh
sf-keyaudit --quiet . && echo "clean" || echo "keys found"
```

Stderr warnings (file size limits, walk errors) are still emitted even in quiet mode.

---

### `-v, --verbose`

Print each file path to stderr as it is scanned.

- **Type**: boolean flag
- **Default**: off

```sh
sf-keyaudit --verbose .
```

Output goes to **stderr** so it does not interfere with the JSON/SARIF report on stdout.

---

### `-h, --help`

Print help text and exit.

```sh
sf-keyaudit -h         # short help
sf-keyaudit --help     # long help with extra detail on some flags
```

---

### `-V, --version`

Print the version string and exit.

```sh
sf-keyaudit -V
# sf-keyaudit v1.0.0  |  Copyright © 2026 Spanforge  |  Build 42
```

---

## Combining flags

Flags compose freely. Common combinations:

```sh
# Fast CI gate: scan only for the two most common providers, stop on first hit
sf-keyaudit --fail-fast --quiet --providers openai,anthropic .

# Full audit with allowlist suppression, output to file
sf-keyaudit --allowlist .sfkeyaudit-allow.yaml --output report.json .

# SARIF for GitHub Code Scanning dashboard
sf-keyaudit --format sarif --output results.sarif .

# Deep scan with symlink traversal and extra ignore file
sf-keyaudit --follow-links --ignore-file .extraignore --max-file-size 52428800 /data
# PR gate: scan only changed files, fail on newly introduced secrets
sf-keyaudit --since-commit origin/main --quiet .

# Full enriched scan: verify + CODEOWNERS + grouped text output
sf-keyaudit --verify --owners --format text --group-by severity .

# Repeated-scan optimisation: cache + archive scanning
sf-keyaudit --cache-file .sfkeyaudit-cache.json --scan-archives .
```

---

## New flags in v2.0

### `--threads <N>`

Number of parallel scan threads.

- **Type**: positive integer
- **Default**: number of logical CPUs

```sh
sf-keyaudit --threads 4 .
```

Reduces CPU usage in resource-constrained environments. Setting `--threads 1` disables parallelism.

---

### `--config <FILE>`

Path to a project configuration file (`.sfkeyaudit.yaml`).

- **Type**: file path
- **Default**: auto-discovered by walking up from PATH to the filesystem root

```sh
sf-keyaudit --config policy/.sfkeyaudit.yaml .
```

When omitted, the tool searches for `.sfkeyaudit.yaml` starting at the scan root and walking up to the filesystem root. Settings in the config file can be overridden by CLI flags. See [Configuration](config.md) for the full format.

---

### `--staged`

Scan only files that have been staged for commit.

- **Type**: boolean flag
- **Requires**: a git repository at or above the scan path
- **Conflicts with**: `--diff-base`, `--since-commit`, `--history`

```sh
sf-keyaudit --staged
```

Equivalent to collecting `git diff --staged --name-only` and scanning those files. Use this in a pre-commit hook to catch secrets before they enter the repository.

---

### `--diff-base <GIT_REF>`

Scan only files changed relative to `GIT_REF`.

- **Type**: git reference (branch name, commit SHA, tag)
- **Requires**: a git repository
- **Conflicts with**: `--staged`, `--since-commit`, `--history`

```sh
sf-keyaudit --diff-base main .
sf-keyaudit --diff-base HEAD~5 .
```

Equivalent to `git diff <GIT_REF> --name-only`. Useful for scanning a feature branch against its target.

---

### `--since-commit <COMMIT_REF>`

Scan all files changed between `COMMIT_REF` and `HEAD`.

- **Type**: git reference
- **Requires**: a git repository
- **Conflicts with**: `--staged`, `--diff-base`, `--history`

```sh
sf-keyaudit --since-commit origin/main .
sf-keyaudit --since-commit v1.0.0 .
```

Equivalent to `git diff <COMMIT_REF>...HEAD --name-only`. Designed for incremental CI scans on pull request branches where you want to check only the commits in the PR.

---

### `--history`

Scan every file ever touched across the full git history.

- **Type**: boolean flag
- **Requires**: a git repository
- **Conflicts with**: `--staged`, `--diff-base`, `--since-commit`

```sh
sf-keyaudit --history .
```

Collects all unique file paths from `git log --all --name-only` and scans each. **Warning**: this can be very slow on large repositories with long histories. Designed for one-time compliance audits.

---

### `--generate-baseline <FILE>`

Write a baseline file containing the fingerprints of all current high-confidence findings.

- **Type**: file path (created or overwritten)
- **Default**: none

```sh
sf-keyaudit --generate-baseline .sfkeyaudit-baseline.json .
```

The baseline file stores stable fingerprints (`fp-` prefixed SHA-256 strings, derived from `pattern_id + file + line`). Run with `--baseline` in subsequent scans to suppress these findings. See [Baseline](baseline.md) for the full reference.

---

### `--baseline <FILE>`

Suppress findings whose fingerprints appear in the baseline file.

- **Type**: file path
- **Default**: none

```sh
sf-keyaudit --baseline .sfkeyaudit-baseline.json .
```

Matching findings are moved to `baselined_findings` in the report and do not trigger exit code 1. New findings with unknown fingerprints still fail the scan. See [Baseline](baseline.md).

---

### `--prune-baseline`

Remove stale entries from the baseline before writing.

- **Type**: boolean flag
- **Requires**: `--generate-baseline`

```sh
sf-keyaudit --baseline .sfkeyaudit-baseline.json \
            --generate-baseline .sfkeyaudit-baseline.json \
            --prune-baseline .
```

A stale entry is one whose fingerprint no longer appears in the current scan results — the key was removed from the codebase. Pruning keeps the baseline compact and prevents approved entries for deleted files from accumulating indefinitely.

---

### `--verify`

Apply offline heuristic validation to each finding and annotate its `validation_status` field.

- **Type**: boolean flag
- **Default**: off

```sh
sf-keyaudit --verify .
```

Validation is performed entirely offline without making any network requests. The heuristics check for:

- Common test markers in the match text (`test`, `example`, `fake`, `mock`, `placeholder`, etc.)
- Repeated characters or patterns (`xxxxxxxxxx`, `1234567890...`)
- Entropy levels consistent with real vs. placeholder values

Possible `validation_status` values:

| Value | Meaning |
|---|---|
| `likely-valid` | No test markers, high entropy — probably a real credential |
| `test-key` | Match text contains known test/placeholder markers |

---

### `--owners`

Enrich findings with CODEOWNERS matches and git blame author information.

- **Type**: boolean flag
- **Default**: off
- **Requires**: a git repository (for blame); CODEOWNERS file (for ownership)

```sh
sf-keyaudit --owners .
```

Two sources are consulted:

1. **CODEOWNERS** — checked at `.github/CODEOWNERS`, `CODEOWNERS`, and `docs/CODEOWNERS` (in that order). Matching owners are written to the `owner` field.
2. **Git blame** — runs `git blame --porcelain -L <line>,<line>` for each finding. The commit author name is written to the `last_author` field.

Both sources are optional. Missing CODEOWNERS or untracked files are silently skipped.

---

### `--scan-archives`

Scan inside compressed archive files found during the walk.

- **Type**: boolean flag
- **Default**: off (archives are silently skipped)

```sh
sf-keyaudit --scan-archives .
```

Supported archive formats: `.zip`, `.tar`, `.tar.gz`, `.tgz`, `.tar.bz2`, `.tar.xz`.

Archive entry paths appear as virtual paths in findings: `archive/path.zip!inner/entry.py`.

---

### `--cache-file <FILE>`

Load and save a hash-based scan cache to speed up repeated scans.

- **Type**: file path (created or updated)
- **Default**: none (caching disabled)

```sh
sf-keyaudit --cache-file .sfkeyaudit-cache.json .
```

On each run, files whose SHA-256 content hash matches the cache and that had zero findings in the previous scan are skipped. Files with findings are always re-scanned. The cache file is human-readable JSON and safe to delete — the next run will rebuild it.

The number of skipped files is reported in `metrics.cached_files_skipped`.

---

### `--group-by <FIELD>`

Group `--format text` output by a specified field.

- **Type**: `file` | `provider` | `severity`
- **Default**: none (findings listed in discovery order)
- **Only affects**: `--format text`

```sh
sf-keyaudit --format text --group-by file .
sf-keyaudit --format text --group-by provider .
sf-keyaudit --format text --group-by severity .```
