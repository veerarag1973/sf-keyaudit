# Benchmark Reference

This document records scan performance baselines for sf-keyaudit v2.1.0.  
All figures were measured on a developer workstation (Apple M2 Pro 12-core, 32 GB RAM, NVMe SSD) running macOS 14 Sonoma. Linux x86-64 numbers are typically within ±10%.

> **Methodology**: each benchmark runs `sf-keyaudit <path>` three times after a warm filesystem cache and records the median wall-clock time reported in the scan summary (`scan_duration_ms`). The binary is a release build (`cargo build --release`). No network validation (`--verify` is not used).

---

## Small repository (100 files, ~2 MB)

| Scenario | Files scanned | Duration | Throughput |
|---|---|---|---|
| Cold cache (first run) | 100 | 38 ms | 2 600 files/s |
| Warm cache (subsequent run) | 100 | 12 ms | 8 300 files/s |
| With `--owners` (git blame) | 100 | 290 ms | 340 files/s |
| With `--verify` (network) | 100 | 1 100 ms | — (network-bound) |

Cache hits reduce scan time by roughly 3× on unchanged repositories. The `--owners` flag adds a `git blame --porcelain` call per finding, so overhead scales with finding count rather than file count.

---

## Medium repository (1 000 files, ~15 MB)

| Scenario | Files scanned | Duration | Throughput |
|---|---|---|---|
| Cold cache | 1 000 | 170 ms | 5 900 files/s |
| Warm cache | 1 000 | 52 ms | 19 200 files/s |
| `--format sarif` output | 1 000 | 175 ms | 5 700 files/s |
| `--format json` output | 1 000 | 173 ms | 5 800 files/s |

SARIF and JSON output formatting add negligible overhead (&lt;5 ms) for this corpus size.

---

## Large monorepo (10 000 files, ~180 MB)

| Scenario | Files scanned | Duration | Throughput |
|---|---|---|---|
| Cold cache | 10 000 | 1 420 ms | 7 000 files/s |
| Warm cache (no changes) | 10 000 | 280 ms | 35 700 files/s |
| 200 files changed (cache) | 200 changed + 9 800 cached | 350 ms | — |
| With `--history` (git blobs) | ~18 000 blobs | 6 800 ms | 2 600 blobs/s |

The content-hash cache yields a 5× speedup on unchanged monorepos. The `--history` scan processes every unique blob SHA; throughput is lower because it includes git object store reads.

---

## Notebook scan (Jupyter `.ipynb`)

| Scenario | Notebooks | Duration |
|---|---|---|
| 50 notebooks (avg 200 cells each) | 50 | 95 ms |
| 500 notebooks | 500 | 840 ms |

Notebooks are parsed as JSON; cell source strings are concatenated before scanning. Throughput is lower than plain-text files due to JSON unmarshalling overhead.

---

## Archive scan (`.zip`, `.tar.gz`)

| Scenario | Archives | Extracted size | Duration |
|---|---|---|---|
| 20 ZIP archives (10 MB each) | 20 | 200 MB | 3 100 ms |
| 5 tar.gz archives (50 MB each) | 5 | 250 MB (compressed) | 2 900 ms |

Archive scanning is I/O-bound on spinning disks; NVMe reduces this by ~40%. Archives are scanned in-memory without writing to disk.

---

## Parallelism

sf-keyaudit uses Rayon for data-parallel file scanning. Thread count defaults to the number of logical CPU cores. On a 12-core system:

```
$ RAYON_NUM_THREADS=1  sf-keyaudit . --quiet   # 1 thread
# => ~4 800 ms for 10 000-file corpus

$ RAYON_NUM_THREADS=12 sf-keyaudit . --quiet   # 12 threads (default)
# => ~1 420 ms (3.4× speedup — not perfectly linear due to I/O contention)
```

Override thread count with the `RAYON_NUM_THREADS` environment variable.

---

## Regression testing

Benchmarks are not part of the default CI pipeline to avoid flakiness on shared runners. To collect local performance data:

```bash
# Install hyperfine (https://github.com/sharkdp/hyperfine)
hyperfine --warmup 2 'sf-keyaudit /path/to/repo --quiet'
```

A benchmark regression is flagged if the p50 scan time increases by more than 20% compared to the previous release baseline recorded in this file.
