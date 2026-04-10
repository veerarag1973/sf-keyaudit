# Contributing to sf-keyaudit

Thank you for taking the time to contribute. This document covers the
contribution workflow, code style expectations, and the process for adding
new detectors or validation providers.

---

## Table of contents

1. [Code of conduct](#code-of-conduct)
2. [How to report a bug](#how-to-report-a-bug)
3. [How to request a feature](#how-to-request-a-feature)
4. [Development setup](#development-setup)
5. [Pull request workflow](#pull-request-workflow)
6. [Adding a new detector](#adding-a-new-detector)
7. [Adding a network validator](#adding-a-network-validator)
8. [Test requirements](#test-requirements)
9. [Commit message format](#commit-message-format)
10. [Security vulnerabilities](#security-vulnerabilities)

---

## Code of conduct

This project follows the [Contributor Covenant v2.1](https://www.contributor-covenant.org/version/2/1/code_of_conduct/).
Be respectful, constructive, and welcoming. Harassment in any form will not be tolerated.

---

## How to report a bug

1. Search [existing issues](../../issues) to avoid duplicates.
2. Open a new issue with the **Bug Report** template.
3. Include:
   - sf-keyaudit version (`sf-keyaudit -V`)
   - OS and Rust toolchain version
   - Minimal reproduction steps
   - Observed vs expected behaviour
   - Sanitised log output (`--verbose` or `RUST_LOG=debug`)

Do **not** include real credentials or secrets in issue descriptions.

---

## How to request a feature

1. Check the [platform maturity roadmap](docs/platform-maturity-roadmap.md) for items already planned.
2. Open an issue with the **Feature Request** template.
3. Describe the use case, not just the implementation.
4. If the feature touches detector patterns, include an example of the secret format.

---

## Development setup

```sh
# Prerequisites: Rust 1.75.0+  (https://rustup.rs)

git clone https://github.com/veerarag1973/sf-keyaudit
cd sf-keyaudit

# Build (debug)
cargo build

# Build (release — matches published binaries)
cargo build --release

# Run all tests
cargo test --locked

# Lint (must be clean before opening a PR)
cargo clippy --locked --all-targets --all-features -- -D warnings

# Format check
cargo fmt --check

# Run only unit tests inside a specific module
cargo test --locked patterns::tests

# Run only integration tests
cargo test --locked --test integration_tests

# Run property tests
cargo test --locked --test property_tests
```

### Environment variables

| Variable | Purpose |
|---|---|
| `RUST_LOG=debug` | Enable debug + trace output to stderr |
| `SF_BUILD_YEAR` | Override build year in version string |
| `SF_BUILD_NUMBER` | Override build number in version string |

---

## Pull request workflow

1. **Fork** the repository and create a branch from `main`:
   ```sh
   git checkout -b feat/my-feature
   ```

2. **Make your changes** following the code style guidelines below.

3. **Add or update tests** — every change that alters observable behaviour
   must include a test. See [Test requirements](#test-requirements).

4. **Run the full check suite locally** before pushing:
   ```sh
   cargo fmt --check
   cargo clippy --locked --all-targets --all-features -- -D warnings
   cargo test --locked
   ```

5. **Open a pull request** against `main` with a clear description:
   - What problem does this solve?
   - What approach did you take?
   - Are there any known limitations or follow-up work?

6. **CI must pass** before a review begins. The CI pipeline checks:
   - formatting (`rustfmt`)
   - linting (`clippy -D warnings`)
   - full test suite (Linux + Windows matrix)
   - secret scan of the PR itself via SARIF upload

7. At least one maintainer approval is required to merge.

### Code style

- Follow `rustfmt` defaults (enforced by CI).
- Prefer `thiserror` error variants over `anyhow` in library code.
- Avoid `unwrap()` except in tests and clearly documented infallible paths.
- Keep functions short. If a function exceeds ~60 lines, split it.
- Use `tracing::{debug, info, warn, trace}` — not `println!` — for diagnostic output.
- All public items must have doc comments if they are part of a module's stable API.

---

## Adding a new detector

Detectors live in `src/patterns.rs` as `PatternDef` entries inside the `defs` array.

### Steps

1. **Identify the format.** Find official documentation for the credential format.
   Note the prefix, length, character set, and any context signals (env var names).

2. **Choose confidence tier:**

   | Tier | When to use |
   |---|---|
   | `High` | Structured prefix + fixed-length body with very low FP rate |
   | `Medium` | Context-sensitive (env var name required to avoid FPs) |
   | `Low` | Heuristic or highly generic pattern; treat as informational |

3. **Write the regex.** Must include `(?P<body>...)`. May include `(?P<prefix>...)`.
   Test it at [regex101.com](https://regex101.com) with the `fancy-regex` flavour.

4. **Set `min_entropy`.** Use `3.5` for most real credentials. Use `3.0` for
   structured formats (connection URLs, PEM headers) where entropy is naturally lower.

5. **Add a `PatternDef` entry** in the appropriate section of `src/patterns.rs`.
   Follow the `{provider}-{keytype}-v{N}` ID convention.

6. **Update the count assertion** in `patterns::tests::build_patterns_count`:
   ```rust
   assert!(p.unwrap().len() >= N, "expected at least N patterns");
   ```

7. **Update `docs/detector-matrix.md`** with a row for the new detector.

8. **Add a provider entry to `docs/providers.md`** if this is a new provider.

### Example PatternDef

```rust
PatternDef {
    id: "acme-api-key-v1",
    provider: "acme",
    description: "ACME Corp API key (acme_ prefix, 32 hex chars)",
    pattern: r"(?P<prefix>acme_)(?P<body>[a-f0-9]{32})",
    min_entropy: 3.5,
    severity: "critical",
    remediation: "Revoke at https://acme.example.com/settings/api-keys and regenerate.",
    confidence: ConfidenceTier::High,
},
```

---

## Adding a network validator

Network validators live in `src/verify.rs` and implement the `ProviderValidator` trait.

### Steps

1. Add a new struct: `struct AcmeValidator;`
2. Implement `ProviderValidator`:
   - `provider_id()` — return the provider slug
   - `validate()` — make the minimum necessary API call; never persist credentials
3. Register the validator in `default_validators()` (or dynamically via `ValidatorRunner::register()`).
4. Add test cases covering `Valid`, `Invalid`, and `RateLimited` outcomes using
   a mock HTTP server (e.g. `wiremock` or `mockito`).
5. Update `docs/providers.md` to mark validation as `network` for the provider.
6. Update `docs/detector-matrix.md` to set the **Network** column to ✅.

### Alternative: declarative validators

For providers that use a simple bearer-token or API-key-header check, you can skip writing Rust code entirely. Add an entry to `custom_validators` in `.sfkeyaudit.yaml`:

```yaml
custom_validators:
  - provider: acme
    endpoint: "https://api.acme.com/v1/me"
    auth_method: bearer
    expect_status: 200
```

See [docs/config.md](docs/config.md#custom_validators) for all supported auth methods.

Validators must:
- Respect the shared `timeout` and `retry` configuration
- Return `ValidationStatus::NetworkError` on transient failures, not `Invalid`
- Never log or store the credential value

---

## Test requirements

| Change type | Required test |
|---|---|
| New detector | At least one `scanner::tests::matches()` call with a positive example |
| Modified detector | Existing tests must still pass; add regression case |
| New subcommand/flag | Integration test in `tests/integration_tests.rs` |
| New baseline/allowlist behaviour | Unit test in `src/baseline.rs` or `src/allowlist.rs` |
| New output format change | Test in `src/output/` module |
| Bug fix | Regression test that would have caught the bug |

Property tests in `tests/property_tests.rs` cover core invariants (entropy bounds,
fingerprint stability, redaction, JSON roundtrip) — extend them if you change those subsystems.

---

## Commit message format

Use [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <short description>

[optional body]

[optional footer: breaking changes, issue refs]
```

Common types: `feat`, `fix`, `docs`, `test`, `refactor`, `perf`, `ci`, `chore`.

Examples:
```
feat(patterns): add GitHub fine-grained PAT detector
fix(baseline): prune no longer panics on empty fingerprint map
docs(cli-reference): document --actor flag default behaviour
test(integration): add triage-store roundtrip test
```

---

## Security vulnerabilities

Do **not** open a public issue for security vulnerabilities.
Follow the process described in [SECURITY.md](SECURITY.md).
