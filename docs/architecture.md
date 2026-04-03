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
| Serialisation | `serde + serde_json + serde_yaml` | JSON report output, YAML allowlist input |
| Error handling | `thiserror 1` | Typed error variants with Display |
| Output IDs | `uuid 1` (v4) | Unique `scan_id` per run |
| Timestamps | `chrono 0.4` | ISO 8601 UTC timestamps |

---

## Module map

```
src/
├── main.rs          Entry point, CLI wiring, parallel scan loop, report assembly
├── cli.rs           Clap-derived Cli struct and --providers parser
├── patterns.rs      All 20 pattern definitions and filter_by_providers()
├── scanner.rs       scan_content() — applies patterns to a single file's text
├── walker.rs        walk() and walk_single_file() — filesystem traversal
├── allowlist.rs     Allowlist YAML loader, matcher, and warning emitter
├── entropy.rs       shannon_entropy() and high-confidence threshold
├── types.rs         Finding, Summary, Report, OutputFormat data types
├── error.rs         AuditError enum and ExitCode enum
└── output/
    ├── mod.rs       render() dispatcher — writes to stdout or file
    ├── json.rs      JSON report serialisation
    └── sarif.rs     SARIF 2.1.0 serialisation
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
  ├─ build_patterns()              compile all regexes once
  ├─ filter_by_providers()         apply --providers filter
  ├─ Allowlist::load()             parse --allowlist YAML (if given)
  │
  ├─ walk(root, config)            discover file paths (ignore engine)
  │      returns Vec<WalkEntry>
  │
  ├─ rayon::par_iter()             parallel across all entries
  │      │
  │      ├─ read_file_content_lossy()   read file bytes, detect binary
  │      └─ scan_content()             apply patterns → Vec<RawFinding>
  │
  ├─ collect and dedup findings    deduplicate same position/pattern
  ├─ assign sequential IDs         f-001, f-002, …
  ├─ Allowlist::apply()            suppress matching entries
  │
  ├─ render()                      JSON or SARIF → stdout or file
  │
  └─ ExitCode::*                   0/1/2/3/4 based on findings + warnings
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
