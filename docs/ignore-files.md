# Ignore Files

sf-keyaudit supports multiple layers of file exclusion, giving you fine-grained control over which files are scanned.

---

## Exclusion layers (applied in order)

1. **Hardcoded always-excluded directories** — cannot be overridden
2. **`.gitignore`** (and `.git/info/exclude`, global gitignore) — standard git ignore chain
3. **`.sfignore`** — project-level tool-specific ignore file
4. **`--ignore-file` files** — extra ignore files passed on the command line

Layers 2–4 can all be disabled at once with `--no-ignore`.

---

## Always-excluded directories

The following directories are always skipped regardless of any flags or ignore files:

| Directory | Reason |
|---|---|
| `.git` | Version control metadata — never contains live credentials |
| `node_modules` | Third-party packages — too large, not your code |
| `target` | Rust build output |
| `dist` | Build output |
| `.venv` / `venv` | Python virtual environments |
| `vendor` | Vendored dependencies |
| `__pycache__` | Python bytecode cache |
| `.mypy_cache` | mypy type-check cache |
| `.pytest_cache` | pytest cache |
| `build` | Generic build output |
| `.next` | Next.js build output |
| `.nuxt` | Nuxt.js build output |

These directories are skipped by directory name anywhere in the tree, not just at the root.

---

## `.gitignore` (automatic)

sf-keyaudit uses the same walking engine as `ripgrep` and respects the full git ignore chain automatically:

- `.gitignore` files at any directory level
- `.git/info/exclude`
- The user's global gitignore (`~/.gitconfig` → `core.excludesFile`)

No configuration required — this is on by default.

To disable: use `--no-ignore`.

---

## `.sfignore`

Place a `.sfignore` file in the **root of the scanned directory**. It uses the same gitignore pattern syntax.

```gitignore
# .sfignore

# Skip generated files
generated/
*.generated.ts

# Skip documentation with example credentials
docs/examples/
*.md

# Skip test fixtures — use allowlist to suppress specific findings instead
tests/fixtures/

# Skip a specific file
config/legacy_keys_backup.yml
```

`.sfignore` patterns are relative to the directory where the file lives.

The `.sfignore` file is only looked for in the scan **root**. It is not searched in subdirectories.

---

## `--ignore-file <FILE>`

Pass one or more external ignore files on the command line. Each file must be in gitignore format.

```sh
# Single extra ignore file
sf-keyaudit --ignore-file .ciignore .

# Multiple extra ignore files
sf-keyaudit --ignore-file .ciignore --ignore-file shared/team.gitignore .
```

Extra ignore files are applied in addition to the standard chain. They apply to the entire scan regardless of their physical location.

`--ignore-file` accepts paths that are:
- Relative to the current working directory
- Absolute paths

If the file does not exist at the given path it is silently skipped (consistent with gitignore tooling behaviour).

---

## `--no-ignore`

Disable all ignore-file processing:

```sh
sf-keyaudit --no-ignore .
```

When `--no-ignore` is set:
- `.gitignore` is not consulted
- `.git/info/exclude` is not consulted
- Global gitignore is not consulted
- `.sfignore` is not consulted
- `--ignore-file` files are not applied

The hardcoded always-excluded directories (`.git`, `node_modules`, `target`, etc.) are **still excluded** even with `--no-ignore`. These cannot be overridden.

---

## Hidden files

Hidden files and directories (names starting with `.`) are **scanned by default**, with the exception of the always-excluded list above. This is intentional because `.env` files, `.netrc`, `.aws/credentials`, and similar are common places for credentials to appear.

---

## Interaction between layers

```
scan .
├── node_modules/            ← always excluded (hardcoded)
├── .git/                    ← always excluded (hardcoded)
├── dist/                    ← always excluded (hardcoded)
├── src/
│   ├── config.py            ← scanned
│   └── generated.py         ← excluded by .sfignore: generated/
├── tests/
│   ├── fixtures/            ← excluded by .sfignore: tests/fixtures/
│   └── test_main.py         ← scanned
├── .env                     ← scanned (hidden files are not excluded by default)
└── docs/
    └── examples.md          ← excluded if docs/ in .sfignore
```

---

## Pattern syntax

`.sfignore` and any `--ignore-file` files use **gitignore pattern syntax**:

| Pattern | Matches |
|---|---|
| `*.log` | All `.log` files anywhere in the tree |
| `logs/` | The `logs` directory (trailing `/` = directory only) |
| `/Makefile` | `Makefile` at root only |
| `docs/**/*.md` | All `.md` files anywhere under `docs/` |
| `!important.log` | Un-ignore `important.log` (negation) |
| `#` comment | Lines starting with `#` are comments |

Full gitignore pattern reference: [git-scm.com/docs/gitignore](https://git-scm.com/docs/gitignore)
