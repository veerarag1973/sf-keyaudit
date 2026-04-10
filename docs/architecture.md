# Architecture

This document describes the internal design of sf-keyaudit for contributors, maintainers, and security reviewers.

---

## Technology stack

| Component | Crate / Version | Purpose |
|---|---|---|
| CLI parsing | `clap 4` (derive) | Argument parsing and `--help` generation |
| Regex engine | `fancy-regex 0.13` | Patterns with lookahead/lookbehind (fallback to PCRE semantics) |
| Directory walker | `ignore 0.4` | ripgrep's walker — gitignore-aware, parallel-friendly |
| Parallelism | `rayon 1` | Parallel file scan across CPU threads |
| Serialisation | `serde + serde_json + serde_yaml` | JSON report output, YAML config/allowlist input |
| Error handling | `thiserror 1` | Typed error variants with Display |
| Output IDs | `uuid 1` (v4) | Unique `scan_id` per run |
| Timestamps | `chrono 0.4` | ISO 8601 UTC timestamps |
| Hashing | `sha2 0.10` | SHA-256 fingerprints and scan cache hashes |
| Archive extraction | `zip 2`, `flate2 1`, `tar 0.4` | In-memory extraction of zip/gzip/tar archives |
| Ordered maps | `indexmap 2` | Deterministic `by_provider` ordering in report output |
| Temp files | `tempfile 3` | Safe temporary paths for archive extraction |
| Config format | `serde_yaml` (reused) | `.sfkeyaudit.yaml` project config and baseline JSON |

---

## Module map

```
src/
├── main.rs          Entry point, CLI wiring, parallel scan loop, report assembly
├── cli.rs           Clap-derived Cli struct, --providers parser, all v2.2 flags (--policy-pack, --triage-store, --audit-log, --actor, --repository, --plugin-dir)
├── config.rs        ProjectConfig loader; auto-discovery; custom rules; severity overrides; policy block; plugin_dirs loader; custom_validators
├── patterns.rs      Built-in pattern definitions and filter_by_providers()
├── scanner.rs       scan_content() — applies patterns to a single file's text
├── walker.rs        walk() and walk_single_file() — filesystem traversal
├── git.rs           Git integration: staged files, --since-commit, --history, blame
├── allowlist.rs     Allowlist YAML loader, matcher, and warning emitter
├── baseline.rs      Baseline generate/load/apply/prune; BaselineEntry with timestamps
├── cache.rs         ScanCache: SHA-256 hash persistence; cached_files_skipped counter
├── ownership.rs     CodeownersMap loader; git blame integration for last_author
├── verify.rs        Offline validation; heuristics → ValidationStatus; 32 network validators; declarative custom validators; ValidatorRunner with dynamic register()
├── fingerprint.rs   fp- prefixed SHA-256 fingerprint derivation
├── entropy.rs       shannon_entropy() and high-confidence threshold
├── policy.rs        Policy evaluation engine; evaluate() against PolicyConfig; block_count()/warn_count(); 4 built-in pack defaults
├── triage.rs        TriageStore: load_or_create/save/set/get/apply; TriageEntry with state + justification + timestamps
├── audit.rs         AuditLog; AuditEventKind (7 variants); append-only JSONL writing
├── types.rs         Finding, Summary, ScanMetrics, Report, PolicyViolation, OutputFormat data types
├── error.rs         AuditError enum and ExitCode enum
└── output/
    ├── mod.rs       render() dispatcher — writes to stdout or file
    ├── json.rs      JSON report serialisation
    ├── sarif.rs     SARIF 2.1.0 serialisation; policyBlockCount/policyWarnCount in run properties
    └── text.rs      Human-readable text output with optional --group-by; POLICY: section
```

---

## Data flow

```
argv
  │
  ▼
parse_cli()  ─── HEADER / VERSION constants (build.rs env vars)
  │
  ▼
run_inner(cli)
  │
  ├─ ProjectConfig::load()          auto-discover .sfkeyaudit.yaml; merge CLI overrides
  ├─ build_patterns()               compile built-in regexes once
  ├─ merge_custom_rules()           append custom patterns from config
  ├─ load_plugin_rules()            load YAML rule files from --plugin-dir directories
  ├─ build_custom_validators()       register declarative validators from config
  ├─ filter_by_providers()          apply --providers filter
  ├─ Allowlist::load()              parse --allowlist YAML (if given)
  ├─ Baseline::load()               parse --baseline JSON (if given)
  ├─ ScanCache::load()              load --cache-file hash DB (if given)
  ├─ CodeownersMap::load()          parse CODEOWNERS (if --owners)
  │
  ├─ git mode dispatch
  │      ├─ --staged           └─ git diff --cached → file list
  │      ├─ --since-commit REF └─ git diff REF...HEAD → file list
  │      └─ --history          └─ git log --all → blob list
  │
  ├─ walk(root, config)             discover file paths (ignore engine)
  │      returns Vec<WalkEntry>
  │
  ├─ rayon::par_iter()              parallel across all entries
  │      │
  │      ├─ cache check                skip if SHA-256 hash unchanged
  │      ├─ archive dispatch            zip/tar → extract → scan members
  │      ├─ notebook dispatch           .ipynb → extract code cells
  │      ├─ read_file_content_lossy()   read bytes, detect binary
  │      └─ scan_content()             apply patterns → Vec<RawFinding>
  │
  ├─ collect and dedup findings      deduplicate same position/pattern
  ├─ fingerprint::compute()          assign fp- SHA-256 per finding
  ├─ assign sequential IDs           f-001, f-002, …
  ├─ Allowlist::apply()              suppress matching entries
  ├─ Baseline::apply_enriched()      suppress baselined; enrich first_seen/last_seen
  ├─ verify::run()                   heuristics → validation_status (if --verify)
  ├─ ownership::enrich()             owner + last_author (if --owners)
  ├─ TriageStore::load_or_create()   load --triage-store JSON (if given)
  │      └─ store.apply()            annotate findings with triage_state + justification
  ├─ evaluate_policy()               apply PolicyConfig → Vec<PolicyViolation> (if --policy-pack)
  │      └─ block_count/warn_count   drive exit code and POLICY: section
  ├─ audit_log.record()              emit ScanCompleted + PolicyViolation events (if --audit-log)
  ├─ ScanCache::flush()              write updated hash DB (if --cache-file)
  │
  ├─ Report { findings, policy_violations, ... }
  ├─ render()                        JSON / SARIF / Text → stdout or file
  │      └─ --group-by routing (text only)
  │
  └─ ExitCode::*                     0/1/2/3/4 based on findings + policy blocks
```

---

## Key design decisions

### Single-pass regex with named capture groups

Each pattern uses `fancy_regex::Regex::captures_iter()` which returns both the full match and all named groups (`prefix`, `body`) in a single pass. This avoids running the regex twice (once for matching, once for group extraction).

The `body` group is the secret portion used for entropy scoring. The `prefix` group is the human-visible prefix preserved in the redacted output string.

### Path-only walker

`walker::walk()` returns only `Vec<WalkEntry>` — file paths and optional warnings, never content. File reading happens inside the rayon worker where each CPU thread holds at most one file's content in memory at a time. This keeps peak memory use proportional to the number of active threads, not the number of files.

### Entropy as a second gate

Pattern matching is necessary but not sufficient. A match that passes all character-class and length constraints can still be a test placeholder if its entropy is low. The per-pattern `min_entropy` threshold eliminates the vast majority of placeholder false positives (repeated strings, sequential characters, documentation examples) without requiring a blocklist of known fake values.

### Allowlist is suppress-on-match, not disable

The allowlist does not disable patterns. Every pattern runs on every file regardless of allowlist contents. A suppressed finding still appears in the scan result internally — it is just excluded from the final `findings` array and exit code calculation. This ensures allowlists are validated against actual findings and stale entries are detected.

### Baseline suppression with fingerprints

The baseline uses `fp-`-prefixed SHA-256 fingerprints derived from `(pattern_id, file, line)` to identify findings across scans. When `--baseline` is passed, findings whose fingerprint matches a baseline entry are moved to `baselined_findings` rather than `findings`. They do not influence the exit code. Baseline entries record `first_seen` and `last_seen` timestamps, which are propagated back into the `Finding` object during `apply_enriched()`.

### Offline verification with heuristics

The `--verify` flag runs heuristic checks on matched key bodies to classify them as `likely-valid` or `test-key`. Checks include: key body entropy relative to provider norms, known test-key prefixes, repeated-character ratio, and sequential-digit ratio. No network calls are made. This keeps the tool safe in air-gapped environments and prevents accidental key validation traffic.

### Hash cache for large repositories

When `--cache-file` is given, sf-keyaudit computes a SHA-256 hash of each file before scanning. If the hash matches a prior run's cache entry and the finding count was zero, the file is skipped. The cache is flushed atomically after the scan completes. `cached_files_skipped` in `ScanMetrics` shows the savings.

### Context-sensitive patterns

Several providers (AWS, Azure OpenAI, Together AI, etc.) use key bodies that are too common in isolation (hex strings, UUIDs). Their patterns require surrounding variable names or HTTP header names. This context sensitivity prevents false positives at the cost of missing keys that appear without any context — which in practice is rare in source code.

### Deduplication

The scan may detect the same key at the same byte offset multiple times if patterns overlap (e.g. a key that matches both a more-specific and a less-specific pattern). Deduplication runs before ID assignment and removes entries with the same `(file, line, column, pattern_id)` tuple.

### Binary file detection

Before scanning, each file's content is checked for null bytes. Files containing a null byte anywhere are considered binary and are skipped silently. This prevents garbled regex behaviour on compiled artifacts, images, and other binary files that may end up in the scan tree.

---

## Build system

### `build.rs`

A Cargo build script runs before compilation and emits two environment variables consumed by `main.rs`:

| Variable | Source | Fallback |
|---|---|---|
| `SF_BUILD_NUMBER` | `GITHUB_RUN_NUMBER` env var | `"0"` |
| `SF_BUILD_YEAR` | Computed from `SystemTime::now()` at compile time | Correct for any year |

The year is computed using a leap-year-aware loop (no external crate dependency in the build script).

### Release profile

```toml
[profile.release]
strip = true          # strip debug symbols → smaller binary
opt-level = 3         # maximum speed optimisation
lto = true            # link-time optimisation across all crates
codegen-units = 1     # single codegen unit for maximum LTO benefit
```

This produces a fully self-contained ~3 MB binary with no external runtime dependencies.

---

## Testing

The test suite is split into two layers:

### Unit tests (`src/`)

Co-located with source modules using `#[cfg(test)]` blocks. Coverage includes:

- Pattern matching (each provider has positive and negative cases)
- Entropy computation edge cases
- Allowlist parsing, matching, and expiry logic
- Walker configuration and ignore behaviour
- Scanner binary detection, line/column calculation, deduplication
- CLI flag parsing
- Output serialisation
- Error dispatch

### Integration tests (`tests/integration_tests.rs`)

Black-box tests using `assert_cmd` that invoke the compiled binary:

- Exit codes for all five conditions
- JSON report field presence and content
- SARIF schema validity
- Provider filter
- Allowlist suppression
- Ignore files
- `--fail-fast`, `--quiet`, `--verbose`
- Single file scan
- `--output` flag
- Symlink traversal (Unix and Windows, with graceful skip when OS privileges are unavailable)
- `--staged` and `--since-commit` (with a temporary git repository fixture)
- `--generate-baseline`, `--baseline`, `--prune-baseline`
- `--verify` validation_status values
- `--owners` enrichment from a synthetic CODEOWNERS file
- `--scan-archives` zip extraction
- `--cache-file` skipping on second scan
- `--format text` and `--group-by` output shape
- Custom rules via `.sfkeyaudit.yaml`
- Severity overrides via config

```sh
cargo test                       # run all tests
cargo test --test integration_tests  # integration tests only
cargo test scanner               # unit tests matching "scanner"
```

---

## Adding a new provider

1. Add a `PatternDef` entry to the `defs` slice in `src/patterns.rs`.
2. Follow the naming convention: `{provider-slug}-{keytype}-v{N}`.
3. Ensure the regex has a named group `(?P<body>...)`. Add `(?P<prefix>...)` if there is a stable prefix.
4. Set `min_entropy` to 3.0 for context-sensitive patterns, 3.5 for prefix-match patterns, 4.0 for patterns with a wide body character class.
5. Add at least two unit tests in `patterns.rs`: one that matches, one that does not.
6. Add an integration test in `tests/integration_tests.rs` that scans a temp file containing a synthetic key.
7. Update [docs/providers.md](providers.md) with the new entry.
