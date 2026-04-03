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

- **Type**: `json` | `sarif`
- **Default**: `json`

```sh
sf-keyaudit --format sarif --output results.sarif .
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
```
