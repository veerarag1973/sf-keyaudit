mod allowlist;
mod baseline;
mod cache;
mod cli;
mod config;
mod entropy;
mod error;
mod fingerprint;
mod git;
mod output;
mod ownership;
mod patterns;
mod scanner;
mod telemetry;
mod types;
mod verify;
mod walker;

use allowlist::{today_utc, Allowlist, AllowlistWarning};
use baseline::Baseline;
use cache::ScanCache;
use chrono::Utc;
use clap::{CommandFactory, FromArgMatches};
use cli::{Cli, GroupByArg, SfSubcommand};
use config::ProjectConfig;
use error::{AuditError, ExitCode};
use ownership::CodeownersMap;
use patterns::{build_custom_patterns, build_patterns, filter_by_providers};
use rayon::prelude::*;
use scanner::{scan_archive_tar, scan_archive_zip, scan_content, scan_notebook_json, RawFinding};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tracing::{debug, info, warn};
use types::{Finding, OutputFormat, Report, ScanMetrics, Summary};
use uuid::Uuid;
use walker::{walk, walk_single_file, WalkConfig, WalkEntry};

/// Full branded header shown above the --help text.
const HEADER: &str = concat!(
    "Spanforge Key Audit  v",
    env!("CARGO_PKG_VERSION"),
    "  |  Copyright \u{00A9} ",
    env!("SF_BUILD_YEAR"),
    " Spanforge  |  Build ",
    env!("SF_BUILD_NUMBER"),
);

/// Version string for -V / --version (clap prepends the binary name automatically).
const VERSION: &str = concat!(
    "v",
    env!("CARGO_PKG_VERSION"),
    "  |  Copyright \u{00A9} ",
    env!("SF_BUILD_YEAR"),
    " Spanforge  |  Build ",
    env!("SF_BUILD_NUMBER"),
);

fn main() {
    // Initialise tracing + optional OpenTelemetry OTLP export.
    // Set OTEL_EXPORTER_OTLP_ENDPOINT to forward spans to a collector.
    // Falls back to stderr-only logging when the env var is absent.
    let _telemetry = telemetry::init();

    let code = run();
    std::process::exit(code);
}

fn run() -> i32 {
    let cli = parse_cli();
    if let Some(SfSubcommand::InstallHooks { path, force }) = &cli.command {
        return dispatch_result(run_install_hooks(path.as_deref(), *force));
    }
    dispatch_result(run_inner(&cli))
}

/// Install pre-commit and pre-push git hooks into `.git/hooks/`.
fn run_install_hooks(
    path: Option<&std::path::Path>,
    force: bool,
) -> Result<ExitCode, AuditError> {
    let repo_root_path = path
        .map(std::path::Path::to_path_buf)
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from(".")));
    let repo_root = git::repo_root(&repo_root_path)?;
    let hooks_dir = repo_root.join(".git").join("hooks");
    std::fs::create_dir_all(&hooks_dir).map_err(|e| {
        AuditError::Config(format!("could not create hooks dir: {e}"))
    })?;

    let hooks: &[(&str, &str)] = &[
        (
            "pre-commit",
            "#!/bin/sh\n# sf-keyaudit pre-commit hook\nset -e\nsf-keyaudit --staged\n",
        ),
        (
            "pre-push",
            concat!(
                "#!/bin/sh\n",
                "# sf-keyaudit pre-push hook\n",
                "set -e\n",
                "# Discover the upstream tracking branch; fall back to scanning everything.\n",
                "UPSTREAM=$(git rev-parse --abbrev-ref '@{upstream}' 2>/dev/null) || UPSTREAM=\"\"\n",
                "if [ -n \"$UPSTREAM\" ]; then\n",
                "    sf-keyaudit --since-commit \"$UPSTREAM\"\n",
                "else\n",
                "    sf-keyaudit .\n",
                "fi\n"
            ),
        ),
    ];

    for (name, script) in hooks {
        let hook_path = hooks_dir.join(name);
        if hook_path.exists() && !force {
            eprintln!(
                "warning: hook already exists at {} — use --force to overwrite",
                hook_path.display()
            );
            continue;
        }
        std::fs::write(&hook_path, script).map_err(|e| {
            AuditError::Config(format!("could not write {name} hook: {e}"))
        })?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&hook_path)
                .map_err(|e| AuditError::Config(format!("stat {name}: {e}")))?               
                .permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&hook_path, perms)
                .map_err(|e| AuditError::Config(format!("chmod {name}: {e}")))?;
        }
        eprintln!("info: installed {} hook at {}", name, hook_path.display());
    }
    Ok(ExitCode::Clean)
}

/// Build the Clap command with the Spanforge branded header injected into the
/// help banner, `-V`, and `--version` output, then parse argv into [`Cli`].
fn parse_cli() -> Cli {
    let matches = Cli::command()
        .before_help(HEADER)
        .version(VERSION)
        .long_version(VERSION)
        .get_matches();
    Cli::from_arg_matches(&matches).unwrap_or_else(|e| e.exit())
}

fn dispatch_result(result: Result<ExitCode, AuditError>) -> i32 {
    match result {
        Ok(code) => code.as_i32(),
        Err(AuditError::ScanRootInvalid(msg)) => {
            eprintln!("error: {msg}");
            ExitCode::ScanError.as_i32()
        }
        Err(AuditError::AllowlistMalformed(msg)) => {
            eprintln!("error: allowlist malformed: {msg}");
            ExitCode::ConfigError.as_i32()
        }
        Err(AuditError::AllowlistMissingReason { file, line }) => {
            eprintln!("error: allowlist entry at {file}:{line} is missing a required `reason` field");
            ExitCode::ConfigError.as_i32()
        }
        Err(AuditError::Config(msg)) => {
            eprintln!("error: {msg}");
            ExitCode::ConfigError.as_i32()
        }
        Err(AuditError::GitError(msg)) => {
            eprintln!("error: git: {msg}");
            ExitCode::ConfigError.as_i32()
        }
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::ScanError.as_i32()
        }
    }
}

fn run_inner(cli: &Cli) -> Result<ExitCode, AuditError> {
    let scan_start = std::time::Instant::now();

    // Root OTel span — fields populated incrementally as data becomes available.
    // When no OTLP endpoint is configured this is a no-op tracing span.
    let root_span = tracing::info_span!(
        "sf-keyaudit.scan",
        "scan.root"          = tracing::field::Empty,
        "scan.files_scanned" = tracing::field::Empty,
        "scan.findings"      = tracing::field::Empty,
        "scan.duration_ms"   = tracing::field::Empty,
    );
    let _span_enter = root_span.enter();

    // ── Resolve scan root ────────────────────────────────────────────────────
    let scan_path = cli
        .path
        .clone()
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| Path::new(".").to_path_buf()));

    if !scan_path.exists() {
        return Err(AuditError::ScanRootInvalid(scan_path.display().to_string()));
    }

    let scan_root = scan_path
        .canonicalize()
        .unwrap_or_else(|_| scan_path.clone());

    root_span.record("scan.root", scan_root.display().to_string().as_str());

    // ── Load project configuration ───────────────────────────────────────────
    let project_config: Option<ProjectConfig> = if let Some(cfg_path) = &cli.config {
        // Explicit config file — load it or error.
        match ProjectConfig::load(cfg_path)? {
            Some(c) => {
                debug!(path = %cfg_path.display(), "loaded explicit config file");
                Some(c)
            }
            None => {
                return Err(AuditError::Config(format!(
                    "config file not found: {}",
                    cfg_path.display()
                )));
            }
        }
    } else {
        // Auto-discover .sfkeyaudit.yaml walking upward from scan root.
        match ProjectConfig::find_and_load(&scan_root)? {
            Some(c) => {
                debug!("auto-discovered config file");
                Some(c)
            }
            None => None,
        }
    };

    // ── Configure rayon thread pool ──────────────────────────────────────────
    let thread_count: Option<usize> = cli.threads.or_else(|| {
        project_config.as_ref().and_then(|c| {
            if c.threads > 0 { Some(c.threads) } else { None }
        })
    });
    if let Some(n) = thread_count {
        if let Err(e) = rayon::ThreadPoolBuilder::new()
            .num_threads(n)
            .build_global()
        {
            // The global pool is often already initialised in tests — log as
            // a warning but continue; the scan still works.
            warn!(threads = n, error = %e, "could not set thread count, using default");
        } else {
            info!(threads = n, "rayon thread pool configured");
        }
    }

    // ── Load and merge patterns ───────────────────────────────────────────────
    let mut all_patterns = build_patterns()?;

    // Prepend custom rules from project config (custom rules take priority).
    if let Some(ref cfg) = project_config {
        if !cfg.custom_rules.is_empty() {
            let custom = build_custom_patterns(&cfg.custom_rules)?;
            info!(count = custom.len(), "loaded custom rules from config");
            let mut merged = custom;
            merged.extend(all_patterns);
            all_patterns = merged;
        }
    }

    // ── Apply severity overrides from project config ──────────────────────────
    if let Some(ref cfg) = project_config {
        if !cfg.severity_overrides.is_empty() {
            for p in all_patterns.iter_mut() {
                if let Some(new_sev) = cfg.severity_overrides.get(&p.id) {
                    p.severity = new_sev.clone();
                }
            }
            debug!(count = cfg.severity_overrides.len(), "applied severity overrides");
        }
    }

    // ── Apply global entropy threshold override from project config ───────────
    if let Some(ref cfg) = project_config {
        if let Some(min_ent) = cfg.min_entropy_override {
            for p in all_patterns.iter_mut() {
                p.min_entropy = min_ent;
            }
            debug!(min_entropy = min_ent, "applied global min_entropy_override");
        }
    }

    // Determine provider filter: CLI wins over config.
    let provider_filter: Vec<String> = {
        let cli_filter = cli.provider_list();
        if !cli_filter.is_empty() {
            cli_filter
        } else if let Some(ref cfg) = project_config {
            cfg.providers.clone().unwrap_or_default()
        } else {
            vec![]
        }
    };

    let active_patterns: Vec<&patterns::Pattern> =
        filter_by_providers(&all_patterns, &provider_filter)?;

    // ── Load allowlist ───────────────────────────────────────────────────────
    // CLI flag takes precedence; falls back to config-level `allowlist` path.
    let allowlist_path = cli.allowlist.as_ref().or_else(|| {
        project_config.as_ref().and_then(|c| c.allowlist.as_ref())
    });
    let allowlist = if let Some(al_path) = allowlist_path {
        if !al_path.exists() {
            return Err(AuditError::Config(format!(
                "allowlist file not found: {}",
                al_path.display()
            )));
        }
        Allowlist::load(al_path)?
    } else {
        Allowlist::empty()
    };

    // ── Load baseline (if --baseline is supplied or config baseline path set) ──
    // CLI flag takes precedence; falls back to config-level `baseline` path.
    let baseline_path = cli.baseline.as_ref().or_else(|| {
        project_config.as_ref().and_then(|c| c.baseline.as_ref())
    });
    let loaded_baseline: Option<Baseline> = if let Some(bl_path) = baseline_path {
        if !bl_path.exists() {
            return Err(AuditError::Config(format!(
                "baseline file not found: {}",
                bl_path.display()
            )));
        }
        let bl = Baseline::load(bl_path)?;
        info!(path = %bl_path.display(), fingerprints = bl.fingerprints.len(), "loaded baseline");
        Some(bl)
    } else {
        None
    };

    // Effective fail_fast: CLI flag OR config-level setting.
    let effective_fail_fast = cli.fail_fast
        || project_config.as_ref().and_then(|c| c.fail_fast).unwrap_or(false);

    // Effective output path: CLI flag OR config-level output_file.
    let effective_output: Option<std::path::PathBuf> = cli.output.clone().or_else(|| {
        project_config.as_ref().and_then(|c| c.output_file.clone())
    });

    // ── Resolve effective max_file_size / max_depth ───────────────────────────
    let max_file_size = project_config
        .as_ref()
        .and_then(|c| c.max_file_size)
        .unwrap_or(cli.max_file_size);

    let max_depth = project_config
        .as_ref()
        .and_then(|c| c.max_depth)
        .or(cli.max_depth);

    // ── Build walk config ────────────────────────────────────────────────────
    let extra_patterns: Vec<String> = project_config
        .as_ref()
        .map(|c| c.ignore_patterns.clone())
        .unwrap_or_default();

    let include_patterns: Vec<String> = project_config
        .as_ref()
        .map(|c| c.include_patterns.clone())
        .unwrap_or_default();

    let walk_config = WalkConfig {
        max_file_size,
        max_depth,
        no_ignore: cli.no_ignore,
        extra_ignore_files: cli.ignore_file.clone(),
        follow_links: cli.follow_links,
        extra_patterns,
        include_patterns,
        scan_archives: cli.scan_archives,
    };

    // ── Collect scannable entries ─────────────────────────────────────────────
    // Git-aware mode: resolve the set of changed/staged files from git and
    // build WalkEntries for those paths only.
    let git_mode = cli.staged
        || cli.diff_base.is_some()
        || cli.since_commit.is_some();

    let (walk_entries, files_skipped_count) = if git_mode {
        let repo_root = git::repo_root(&scan_root)?;
        let git_files = if cli.staged {
            info!("git staged mode: scanning staged files only");
            git::staged_files(&repo_root)?
        } else if let Some(ref base_ref) = cli.diff_base {
            info!(base_ref = base_ref, "git diff mode: scanning changed files");
            git::diff_files(&repo_root, base_ref)?
        } else if let Some(ref since_ref) = cli.since_commit {
            info!(since_ref = since_ref, "git since-commit mode: scanning files changed since ref");
            git::since_commit_files(&repo_root, since_ref)?
        } else {
            unreachable!("git_mode is only set when staged, diff_base, or since_commit is active")
        };

        let mut entries: Vec<WalkEntry> = Vec::new();
        let mut skipped = 0usize;
        for abs_path in git_files {
            if !abs_path.starts_with(&scan_root) {
                continue;
            }
            match abs_path.metadata() {
                Ok(meta) if meta.is_file() => {
                    if meta.len() > max_file_size {
                        warn!(
                            path = %abs_path.display(),
                            size = meta.len(),
                            limit = max_file_size,
                            "skipping oversized git file"
                        );
                        skipped += 1;
                        continue;
                    }
                    entries.push(WalkEntry { path: abs_path, warning: None });
                }
                _ => continue,
            }
        }
        (entries, skipped)
    } else if scan_path.is_file() {
        let entries = walk_single_file(&scan_path, &walk_config);
        let skipped = entries.iter().filter(|e| e.warning.is_some()).count();
        (entries, skipped)
    } else {
        let entries = walk(&scan_root, &walk_config);
        let skipped = entries.iter().filter(|e| e.warning.is_some()).count();
        (entries, skipped)
    };

    // Emit walk warnings to stderr.
    for entry in &walk_entries {
        if let Some(warn_msg) = &entry.warning {
            eprintln!("warning: {warn_msg}");
        }
    }

    // ── Keep only entries without warnings (scannable files). ─────────────────
    let scannable: Vec<_> = walk_entries
        .into_iter()
        .filter(|e| e.warning.is_none())
        .collect();

    let files_scanned = scannable.len();

    // ── Load scan cache (--cache-file) ────────────────────────────────────────
    // ScanCache::load returns Self directly (never fails; returns empty on error).
    let mut scan_cache: Option<ScanCache> = if let Some(ref cache_path) = cli.cache_file {
        let c = ScanCache::load(cache_path);
        info!(path = %cache_path.display(), "loaded scan cache");
        Some(c)
    } else {
        None
    };

    // ── Load CODEOWNERS map (--owners) ────────────────────────────────────────
    // CodeownersMap::load returns Option<Self> directly (None when not found).
    let codeowners_map: Option<CodeownersMap> = if cli.owners {
        let m = CodeownersMap::load(&scan_root);
        if m.is_some() {
            info!("loaded CODEOWNERS map");
        } else {
            warn!("CODEOWNERS not found; owner enrichment disabled");
        }
        m
    } else {
        None
    };

    // ── Parallel read + pattern matching ─────────────────────────────────────
    let fail_fast_flag = Arc::new(AtomicBool::new(false));
    let cached_files_skipped = std::sync::atomic::AtomicUsize::new(0);
    let notebooks_scanned = std::sync::atomic::AtomicUsize::new(0);
    let archives_scanned = std::sync::atomic::AtomicUsize::new(0);
    // Collect (path, hash, findings_count) tuples for cache update after par_iter.
    let cache_update_queue: std::sync::Mutex<Vec<(String, String, usize)>> =
        std::sync::Mutex::new(Vec::new());

    let walk_raw_findings: Vec<RawFinding> = scannable
        .par_iter()
        .flat_map(|entry| {
            if effective_fail_fast && fail_fast_flag.load(Ordering::Relaxed) {
                return vec![];
            }

            // Compute relative path from scan_root.
            let rel_path = if scan_path.is_file() {
                entry
                    .path
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_else(|| entry.path.display().to_string())
            } else {
                pathdiff::entry_relative(&scan_root, &entry.path)
            };

            if cli.verbose {
                eprintln!("scanning: {rel_path}");
            }
            debug!(path = %rel_path, "scanning file");

            // ── Cache check ── ─────────────────────────────────────────────
            // Read raw bytes to compute hash (needed even for cache check).
            let raw_bytes = match std::fs::read(&entry.path) {
                Ok(b) => b,
                Err(err) => {
                    eprintln!("warning: cannot read {}: {err}", entry.path.display());
                    return vec![];
                }
            };

            // If scan_cache is Some, check whether this file has already been
            // scanned with the same content hash and yielded 0 findings.
            // (We only skip when the cached finding count is 0, to avoid
            // missing new-baseline suppressions in subsequent runs.)
            if let Some(ref sc) = scan_cache {
                let hash = cache::sha256_hex(&raw_bytes);
                if let Some(entry_cache) = sc.check(&rel_path, &hash) {
                    if entry_cache.findings_count == 0 {
                        cached_files_skipped.fetch_add(1, Ordering::Relaxed);
                        return vec![];
                    }
                }
            }

            // ── Binary / notebook / archive dispatch ───────────────────────
            let ext = entry
                .path
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or("")
                .to_lowercase();

            // Archives
            if cli.scan_archives
                && matches!(ext.as_str(), "zip" | "tar" | "gz" | "tgz" | "bz2" | "xz")
            {
                archives_scanned.fetch_add(1, Ordering::Relaxed);
                let mut results = if ext == "zip" {
                    scan_archive_zip(&entry.path, &scan_root, &active_patterns)
                } else {
                    scan_archive_tar(&entry.path, &scan_root, &active_patterns)
                };
                if effective_fail_fast && !results.is_empty() {
                    fail_fast_flag.store(true, Ordering::Relaxed);
                }
                return results;
            }

            // Binary check
            if scanner::is_binary(&raw_bytes) {
                return vec![];
            }

            let content = match std::str::from_utf8(&raw_bytes) {
                Ok(s) => s.to_string(),
                Err(_) => String::from_utf8_lossy(&raw_bytes).into_owned(),
            };

            // Jupyter notebooks
            let file_findings = if ext == "ipynb" {
                notebooks_scanned.fetch_add(1, Ordering::Relaxed);
                scan_notebook_json(&rel_path, &content, &active_patterns)
            } else {
                scan_content(&rel_path, &content, &active_patterns)
            };

            // Queue cache update for this file (applied after par_iter completes).
            if cli.cache_file.is_some() {
                let hash = cache::sha256_hex(&raw_bytes);
                cache_update_queue
                    .lock()
                    .unwrap()
                    .push((rel_path.clone(), hash, file_findings.len()));
            }

            if effective_fail_fast && !file_findings.is_empty() {
                fail_fast_flag.store(true, Ordering::Relaxed);
            }

            file_findings
        })
        .collect();

    // ── History mode: replace walk results with git-blob scan ──────────────
    // When --history is active, scan every blob ever stored in the git object
    // database instead of the on-disk working tree.  This is the correct
    // approach: it finds credentials in deleted files and old commits too.
    let (raw_findings, files_scanned) = if cli.history {
        let repo_root = git::repo_root(&scan_root)?;
        info!("git history mode: scanning all blobs in full git object history");
        let blobs = git::history_blobs(&repo_root, max_file_size)?;
        let blob_count = blobs.len();
        let history_raw: Vec<RawFinding> = blobs
            .into_par_iter()
            .flat_map(|blob| {
                if scanner::is_binary(&blob.content) {
                    return vec![];
                }
                let content = String::from_utf8_lossy(&blob.content).into_owned();
                let ext = std::path::Path::new(&blob.filename)
                    .extension()
                    .and_then(|e| e.to_str())
                    .unwrap_or("")
                    .to_lowercase();
                if ext == "ipynb" {
                    scan_notebook_json(&blob.filename, &content, &active_patterns)
                } else {
                    scan_content(&blob.filename, &content, &active_patterns)
                }
            })
            .collect();
        (history_raw, blob_count)
    } else {
        (walk_raw_findings, files_scanned)
    };

    let total_raw_matches = raw_findings.len();
    let cached_skipped = cached_files_skipped.load(Ordering::Relaxed);
    let nb_scanned = notebooks_scanned.load(Ordering::Relaxed);
    let arch_scanned = archives_scanned.load(Ordering::Relaxed);

    // Apply queued cache updates (sequential, safe after par_iter).
    if let Some(ref mut sc) = scan_cache {
        if let Ok(updates) = cache_update_queue.into_inner() {
            for (path, hash, count) in updates {
                sc.update(path, hash, count);
            }
        }
    }

    // Flush cache to disk if it was used.
    if let Some(ref sc) = scan_cache {
        if let Some(ref cache_path) = cli.cache_file {
            if let Err(e) = sc.save(cache_path) {
                warn!(error = %e, "could not save scan cache");
            }
        }
    }

    // ── Assign sequential IDs and split high / low confidence ────────────────
    let mut seq = 1usize;
    let mut findings: Vec<Finding> = Vec::new();
    let mut low_confidence: Vec<Finding> = Vec::new();

    for raw in raw_findings {
        let finding = Finding {
            id: format!("f-{:03}", seq),
            fingerprint: raw.fingerprint.clone(),
            provider: raw.provider.clone(),
            file: raw.file.clone(),
            line: raw.line,
            column: raw.column,
            match_text: raw.match_text.clone(),
            pattern_id: raw.pattern_id.clone(),
            severity: raw.severity.clone(),
            entropy: raw.entropy,
            remediation: if raw.remediation.is_empty() {
                None
            } else {
                Some(raw.remediation.clone())
            },
            validation_status: None,
            first_seen: None,
            last_seen: None,
            owner: None,
            last_author: None,
            suppression_provenance: None,
            secret_body: Some(raw.secret_body.clone()),
        };
        seq += 1;
        if raw.high_confidence {
            findings.push(finding);
        } else {
            low_confidence.push(finding);
        }
    }

    let high_confidence_count = findings.len();
    let low_confidence_count = low_confidence.len();

    // ── Apply allowlist ───────────────────────────────────────────────────────
    let today = today_utc();
    let (suppressed, active_findings, al_warnings) = allowlist.apply(&findings, today);
    let suppressed_count = suppressed.len();

    // Emit allowlist warnings to stderr.
    for w in &al_warnings {
        match w {
            AllowlistWarning::Expired { pattern_id, file, line } => {
                warn!(
                    pattern_id = %pattern_id,
                    file = %file,
                    line = line,
                    "allowlist entry expired"
                );
                eprintln!(
                    "warning: allowlist entry {pattern_id} at {file}:{line} has expired and is no longer suppressing"
                );
            }
            AllowlistWarning::Unmatched { pattern_id, file, line } => {
                warn!(
                    pattern_id = %pattern_id,
                    file = %file,
                    line = line,
                    "allowlist entry unmatched"
                );
                eprintln!(
                    "warning: allowlist entry {pattern_id} at {file}:{line} no longer matches any finding"
                );
            }
        }
    }

    if !suppressed.is_empty() && !cli.quiet {
        eprintln!(
            "info: {} finding(s) suppressed by allowlist",
            suppressed.len()
        );
    }

    // ── Offline validation (--verify) ─────────────────────────────────────────
    let active_findings = if cli.verify {
        info!("running offline validation on {} findings", active_findings.len());
        let findings = verify::apply_offline_validation(active_findings);
        // Network validation is opt-in: set SFKEYAUDIT_NETWORK_VERIFY=1 together
        // with --verify to make live HTTP liveness checks against provider APIs.
        // WARNING: transmits key material — only use in isolated CI environments.
        if std::env::var("SFKEYAUDIT_NETWORK_VERIFY").as_deref() == Ok("1") {
            info!("running network validation on {} findings", findings.len());
            verify::apply_network_validation(findings)
        } else {
            findings
        }
    } else {
        active_findings
    };

    // ── Owner and blame enrichment (--owners) ─────────────────────────────────
    let active_findings: Vec<Finding> = if cli.owners {
        if let Some(ref comap) = codeowners_map {
            active_findings
                .into_iter()
                .map(|mut f| {
                    let owners = comap.owners_for(&f.file);
                    if !owners.is_empty() {
                        f.owner = Some(owners.join(", "));
                    }
                    // git blame for the specific line
                    if let Ok(ref repo_root) = git::repo_root(&scan_root) {
                        if let Some(blame) = ownership::blame_line(repo_root, &f.file, f.line) {
                            f.last_author = Some(blame.author.clone());
                        }
                    }
                    f
                })
                .collect()
        } else {
            active_findings
        }
    } else {
        active_findings
    };

    // ── Apply baseline ────────────────────────────────────────────────────────
    // Partition: (new findings, baselined findings).
    let (final_findings, baselined_findings): (Vec<Finding>, Vec<Finding>) =
        if let Some(ref bl) = loaded_baseline {
            // apply_enriched returns owned findings with first_seen / last_seen
            // / suppression_provenance populated from the baseline entries.
            let (new_owned, baselined_owned) = bl.apply_enriched(&active_findings);
            info!(
                baselined = baselined_owned.len(),
                remaining = new_owned.len(),
                "baseline applied"
            );
            if !baselined_owned.is_empty() && !cli.quiet {
                eprintln!(
                    "info: {} finding(s) suppressed by baseline",
                    baselined_owned.len()
                );
            }
            (new_owned, baselined_owned)
        } else {
            (active_findings, vec![])
        };
    let baselined_count = baselined_findings.len();

    // ── Generate baseline file (--generate-baseline) ─────────────────────────
    if let Some(bl_path) = &cli.generate_baseline {
        let all_findings: Vec<Finding> = final_findings
            .iter()
            .chain(baselined_findings.iter())
            .cloned()
            .collect();
        let mut bl = Baseline::generate(&all_findings, env!("CARGO_PKG_VERSION"));

        // Preserve first_seen timestamps and approval metadata from the existing
        // baseline so that re-generated baselines don't lose historical context.
        if let Some(ref existing_bl) = loaded_baseline {
            for (fp, old_entry) in &existing_bl.fingerprints {
                if let Some(new_entry) = bl.fingerprints.get_mut(fp) {
                    new_entry.first_seen = old_entry.first_seen.clone();
                    new_entry.approved_by = old_entry.approved_by.clone();
                    new_entry.approved_at = old_entry.approved_at.clone();
                }
            }
        }

        // Prune stale entries before writing (--prune-baseline).
        if cli.prune_baseline {
            let removed = bl.prune(&all_findings);
            if !removed.is_empty() && !cli.quiet {
                eprintln!("info: pruned {} stale baseline entries", removed.len());
            }
        }

        // ── Record approval metadata (--baseline-approved-by / env var) ───────
        // CLI flag takes precedence; falls back to SFKEYAUDIT_APPROVED_BY env var.
        let env_approved_by = std::env::var("SFKEYAUDIT_APPROVED_BY").ok();
        let approved_by = cli
            .baseline_approved_by
            .as_deref()
            .or(env_approved_by.as_deref());

        if let Some(who) = approved_by {
            let now = Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
            bl.approved_by = Some(who.to_string());
            bl.approved_at = Some(now.clone());
            for entry in bl.fingerprints.values_mut() {
                entry.approved_by = Some(who.to_string());
                entry.approved_at = Some(now.clone());
            }
            if !cli.quiet {
                eprintln!("info: baseline approved by '{who}' at {now}");
            }
            info!(approved_by = who, approved_at = %now, "baseline approval recorded");
        }

        bl.save(bl_path)?;
        if !cli.quiet {
            eprintln!(
                "info: baseline with {} fingerprint(s) written to {}",
                bl.fingerprints.len(),
                bl_path.display()
            );
        }
        info!(
            path = %bl_path.display(),
            fingerprints = bl.fingerprints.len(),
            "baseline written"
        );
    }

    // ── Set first_seen / last_seen on new findings ────────────────────────────
    // Findings whose timestamps were populated by the baseline retain those values.
    // Genuinely new findings get the current scan timestamp.
    let scan_timestamp = Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let final_findings: Vec<Finding> = final_findings
        .into_iter()
        .map(|mut f| {
            if f.first_seen.is_none() {
                f.first_seen = Some(scan_timestamp.clone());
            }
            if f.last_seen.is_none() {
                f.last_seen = Some(scan_timestamp.clone());
            }
            f
        })
        .collect();

    // ── Collect scan metrics ──────────────────────────────────────────────────
    let scan_duration_ms = scan_start.elapsed().as_millis() as u64;
    let metrics = ScanMetrics {
        scan_duration_ms,
        files_skipped: files_skipped_count,
        total_raw_matches,
        high_confidence_count,
        low_confidence_count,
        suppressed_count,
        baselined_count,
        notebooks_scanned: nb_scanned,
        archives_scanned: arch_scanned,
        cached_files_skipped: cached_skipped,
    };

    // Populate the root OTel span with final scan metrics.
    root_span
        .record("scan.files_scanned", files_scanned as u64)
        .record("scan.findings", final_findings.len() as u64)
        .record("scan.duration_ms", scan_duration_ms as u64);

    info!(
        files_scanned = files_scanned,
        findings = final_findings.len(),
        low_confidence = low_confidence_count,
        suppressed = suppressed_count,
        baselined = baselined_count,
        duration_ms = scan_duration_ms,
        "scan complete"
    );

    // ── Build report ──────────────────────────────────────────────────────────
    let summary = Summary::from_findings(&final_findings);
    let report = Report {
        scan_id: Uuid::new_v4().to_string(),
        tool: "sf-keyaudit".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        timestamp: Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        scan_root: scan_root.display().to_string(),
        files_scanned,
        findings: final_findings.clone(),
        low_confidence_findings: low_confidence,
        baselined_findings,
        summary,
        metrics,
    };

    // ── Output ────────────────────────────────────────────────────────────────
    if !cli.quiet {
        // Resolve output format: CLI flag > config default_format > json.
        let format: OutputFormat = cli
            .format
            .map(|f| f.into())
            .or_else(|| {
                project_config.as_ref().and_then(|c| {
                    c.default_format.as_deref().and_then(|s| match s {
                        "json"  => Some(OutputFormat::Json),
                        "sarif" => Some(OutputFormat::Sarif),
                        "text"  => Some(OutputFormat::Text),
                        _ => None,
                    })
                })
            })
            .unwrap_or(OutputFormat::Json);

        // Detect color: only when writing text to a real stdout terminal.
        use std::io::IsTerminal;
        let use_color = format == OutputFormat::Text
            && effective_output.is_none()
            && std::io::stdout().is_terminal();

        // For text output, delegate to the color-aware renderer.
        let rendered_text: Option<String> = if format == OutputFormat::Text {
            let group = match cli.group_by {
                Some(GroupByArg::File) => Some(output::text::GroupBy::File),
                Some(GroupByArg::Provider) => Some(output::text::GroupBy::Provider),
                Some(GroupByArg::Severity) => Some(output::text::GroupBy::Severity),
                None => None,
            };
            Some(output::text::render_with_options(&report, group, use_color)?)
        } else {
            None
        };

        if let Some(text) = rendered_text {
            match effective_output.as_deref() {
                Some(path) => std::fs::write(path, &text).map_err(|source| {
                    AuditError::OutputWrite {
                        path: path.display().to_string(),
                        source,
                    }
                })?,
                None => println!("{text}"),
            }
        } else {
            match output::render(&report, format, effective_output.as_deref())? {
                Some(text) => println!("{text}"),
                None => {} // written to file
            }
        }
    }

    // ── Determine exit code ───────────────────────────────────────────────────
    let has_allowlist_issues = !al_warnings.is_empty();

    if !final_findings.is_empty() {
        Ok(ExitCode::Findings)
    } else if has_allowlist_issues {
        Ok(ExitCode::AllowlistWarn)
    } else {
        Ok(ExitCode::Clean)
    }
}

/// Tiny path utility — compute relative path from base to target.
mod pathdiff {
    use std::path::{Path, PathBuf};

    pub fn entry_relative(base: &Path, target: &Path) -> String {
        let rel: PathBuf = target
            .strip_prefix(base)
            .map(|r| r.to_path_buf())
            .unwrap_or_else(|_| target.to_path_buf());
        // Normalise separators to forward-slash for cross-platform output.
        rel.display().to_string().replace('\\', "/")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::OutputFormatArg;
    use std::fs;
    use tempfile::TempDir;

    /// Construct a minimal Cli pointing at `path`.
    fn make_cli(path: std::path::PathBuf) -> Cli {
        Cli {
            path: Some(path),
            output: None,
            format: None,
            fail_fast: false,
            no_ignore: false,
            ignore_file: vec![],
            max_file_size: 10 * 1024 * 1024,
            max_depth: None,
            providers: None,
            allowlist: None,
            quiet: false,
            verbose: false,
            follow_links: false,
            config: None,
            threads: None,
            generate_baseline: None,
            baseline: None,
            staged: false,
            diff_base: None,
            since_commit: None,
            history: false,
            verify: false,
            group_by: None,
            owners: false,
            scan_archives: false,
            cache_file: None,
            prune_baseline: false,
            baseline_approved_by: None,
            command: None,
        }
    }

    fn tmpdir() -> TempDir {
        tempfile::tempdir().unwrap()
    }

    // ── pathdiff ──────────────────────────────────────────────────────────────

    #[test]
    fn pathdiff_strips_base_prefix() {
        let base = std::path::Path::new("/project");
        let target = std::path::Path::new("/project/src/main.rs");
        let rel = pathdiff::entry_relative(base, target);
        assert_eq!(rel, "src/main.rs");
    }

    #[test]
    fn pathdiff_falls_back_when_not_under_base() {
        let base = std::path::Path::new("/other");
        let target = std::path::Path::new("/project/src/main.rs");
        let rel = pathdiff::entry_relative(base, target);
        assert!(rel.contains("main.rs"));
    }

    #[test]
    fn pathdiff_normalizes_backslashes() {
        let s = "src\\lib\\mod.rs".replace('\\', "/");
        assert_eq!(s, "src/lib/mod.rs");
    }

    // ── dispatch_result ───────────────────────────────────────────────────────

    #[test]
    fn dispatch_ok_returns_correct_exit_code() {
        assert_eq!(dispatch_result(Ok(ExitCode::Clean)), 0);
        assert_eq!(dispatch_result(Ok(ExitCode::Findings)), 1);
        assert_eq!(dispatch_result(Ok(ExitCode::AllowlistWarn)), 4);
    }

    #[test]
    fn dispatch_scan_root_invalid_returns_scan_error() {
        let r = dispatch_result(Err(AuditError::ScanRootInvalid("no/path".to_string())));
        assert_eq!(r, ExitCode::ScanError.as_i32());
    }

    #[test]
    fn dispatch_allowlist_malformed_returns_config_error() {
        let r = dispatch_result(Err(AuditError::AllowlistMalformed("bad yaml".to_string())));
        assert_eq!(r, ExitCode::ConfigError.as_i32());
    }

    #[test]
    fn dispatch_allowlist_missing_reason_returns_config_error() {
        let r = dispatch_result(Err(AuditError::AllowlistMissingReason {
            file: "allow.yaml".to_string(),
            line: 3,
        }));
        assert_eq!(r, ExitCode::ConfigError.as_i32());
    }

    #[test]
    fn dispatch_config_error_returns_config_error() {
        let r = dispatch_result(Err(AuditError::Config("bad opt".to_string())));
        assert_eq!(r, ExitCode::ConfigError.as_i32());
    }

    #[test]
    fn dispatch_io_error_returns_scan_error() {
        let io_err = std::io::Error::from(std::io::ErrorKind::PermissionDenied);
        let r = dispatch_result(Err(AuditError::Io(io_err)));
        assert_eq!(r, ExitCode::ScanError.as_i32());
    }

    #[test]
    fn dispatch_git_error_returns_config_error() {
        let r = dispatch_result(Err(AuditError::GitError("not a git repo".to_string())));
        assert_eq!(r, ExitCode::ConfigError.as_i32());
    }

    // ── run_inner: clean scan ─────────────────────────────────────────────────

    #[test]
    fn run_inner_clean_scan_returns_exit_clean() {
        let dir = tmpdir();
        fs::write(dir.path().join("clean.py"), b"print('hello')\n").unwrap();
        let cli = make_cli(dir.path().to_path_buf());
        let result = run_inner(&cli).unwrap();
        assert_eq!(result, ExitCode::Clean);
    }

    // ── run_inner: key finding ────────────────────────────────────────────────

    #[test]
    fn run_inner_returns_findings_exit_code() {
        let dir = tmpdir();
        // OpenAI legacy key: sk- + exactly 48 alphanumeric chars
        let key = "sk-xK9pQm7vL3nRwT5yJbHfDcGsEaZuViYo4W8MiNqX2Pe5AbcD";
        fs::write(dir.path().join("keys.py"), format!("KEY='{key}'\n").as_bytes()).unwrap();
        let cli = make_cli(dir.path().to_path_buf());
        let result = run_inner(&cli).unwrap();
        assert_eq!(result, ExitCode::Findings);
    }

    // ── run_inner: nonexistent path ───────────────────────────────────────────

    #[test]
    fn run_inner_nonexistent_path_returns_scan_root_invalid() {
        let cli = make_cli(std::path::PathBuf::from("/no/such/path/at/all/xyz"));
        let result = run_inner(&cli);
        assert!(matches!(result, Err(AuditError::ScanRootInvalid(_))));
    }

    // ── run_inner: allowlist missing file ─────────────────────────────────────

    #[test]
    fn run_inner_missing_allowlist_file_returns_config_error() {
        let dir = tmpdir();
        fs::write(dir.path().join("clean.py"), b"x=1\n").unwrap();
        let mut cli = make_cli(dir.path().to_path_buf());
        cli.allowlist = Some(dir.path().join("nonexistent_allowlist.yaml"));
        let result = run_inner(&cli);
        assert!(matches!(result, Err(AuditError::Config(_))));
    }

    // ── run_inner: allowlist unmatched entry → AllowlistWarn ─────────────────

    #[test]
    fn run_inner_allowlist_unmatched_entry_returns_allowlist_warn() {
        let dir = tmpdir();
        fs::write(dir.path().join("clean.py"), b"x = 1\n").unwrap();
        let allowlist_yaml = "allowlist:\n  - pattern_id: openai-legacy-key-v1\n    file: nonexistent.py\n    line: 1\n    reason: \"stale entry\"\n";
        let al_path = dir.path().join(".sfkeyaudit-allow.yaml");
        fs::write(&al_path, allowlist_yaml.as_bytes()).unwrap();
        let mut cli = make_cli(dir.path().to_path_buf());
        cli.allowlist = Some(al_path);
        let result = run_inner(&cli).unwrap();
        assert_eq!(result, ExitCode::AllowlistWarn);
    }

    // ── run_inner: allowlist suppresses the only finding → Clean ─────────────

    #[test]
    fn run_inner_allowlist_suppresses_finding_returns_clean() {
        let dir = tmpdir();
        let key = "sk-xK9pQm7vL3nRwT5yJbHfDcGsEaZuViYo4W8MiNqX2Pe5AbcD";
        fs::write(dir.path().join("mock.py"), format!("KEY='{key}'\n").as_bytes()).unwrap();
        let allowlist_yaml = "allowlist:\n  - pattern_id: openai-legacy-key-v1\n    file: mock.py\n    line: 1\n    reason: \"test fixture\"\n";
        let al_path = dir.path().join(".sfkeyaudit-allow.yaml");
        fs::write(&al_path, allowlist_yaml.as_bytes()).unwrap();
        let mut cli = make_cli(dir.path().to_path_buf());
        cli.allowlist = Some(al_path);
        let result = run_inner(&cli).unwrap();
        assert_eq!(result, ExitCode::Clean);
    }

    // ── run_inner: single file scan ───────────────────────────────────────────

    #[test]
    fn run_inner_single_file_with_key_returns_findings() {
        let dir = tmpdir();
        let key = "sk-xK9pQm7vL3nRwT5yJbHfDcGsEaZuViYo4W8MiNqX2Pe5AbcD";
        let fpath = dir.path().join("secret.py");
        fs::write(&fpath, format!("KEY='{key}'\n").as_bytes()).unwrap();
        let cli = make_cli(fpath);
        let result = run_inner(&cli).unwrap();
        assert_eq!(result, ExitCode::Findings);
    }

    #[test]
    fn run_inner_single_clean_file_returns_clean() {
        let dir = tmpdir();
        let fpath = dir.path().join("clean.py");
        fs::write(&fpath, b"x = 1\n").unwrap();
        let cli = make_cli(fpath);
        let result = run_inner(&cli).unwrap();
        assert_eq!(result, ExitCode::Clean);
    }

    // ── run_inner: providers filter ───────────────────────────────────────────

    #[test]
    fn run_inner_provider_filter_excludes_non_matching_key() {
        let dir = tmpdir();
        let key = "sk-xK9pQm7vL3nRwT5yJbHfDcGsEaZuViYo4W8MiNqX2Pe5AbcD";
        fs::write(dir.path().join("keys.py"), format!("KEY='{key}'\n").as_bytes()).unwrap();
        let mut cli = make_cli(dir.path().to_path_buf());
        cli.providers = Some("anthropic".to_string());
        let result = run_inner(&cli).unwrap();
        assert_eq!(result, ExitCode::Clean);
    }

    // ── run_inner: quiet mode ─────────────────────────────────────────────────

    #[test]
    fn run_inner_quiet_mode_still_returns_correct_exit_code() {
        let dir = tmpdir();
        let key = "sk-xK9pQm7vL3nRwT5yJbHfDcGsEaZuViYo4W8MiNqX2Pe5AbcD";
        fs::write(dir.path().join("keys.py"), format!("KEY='{key}'\n").as_bytes()).unwrap();
        let mut cli = make_cli(dir.path().to_path_buf());
        cli.quiet = true;
        let result = run_inner(&cli).unwrap();
        assert_eq!(result, ExitCode::Findings);
    }

    // ── run_inner: verbose flag ───────────────────────────────────────────────

    #[test]
    fn run_inner_verbose_flag_does_not_change_exit_code() {
        let dir = tmpdir();
        fs::write(dir.path().join("clean.py"), b"x=1\n").unwrap();
        let mut cli = make_cli(dir.path().to_path_buf());
        cli.verbose = true;
        let result = run_inner(&cli).unwrap();
        assert_eq!(result, ExitCode::Clean);
    }

    // ── run_inner: fail-fast ──────────────────────────────────────────────────

    #[test]
    fn run_inner_fail_fast_returns_findings_on_first_key() {
        let dir = tmpdir();
        let key = "sk-xK9pQm7vL3nRwT5yJbHfDcGsEaZuViYo4W8MiNqX2Pe5AbcD";
        fs::write(dir.path().join("a.py"), format!("K='{key}'\n").as_bytes()).unwrap();
        fs::write(dir.path().join("b.py"), format!("K='{key}'\n").as_bytes()).unwrap();
        let mut cli = make_cli(dir.path().to_path_buf());
        cli.fail_fast = true;
        cli.quiet = true;
        let result = run_inner(&cli).unwrap();
        assert_eq!(result, ExitCode::Findings);
    }

    // ── run_inner: output to file ─────────────────────────────────────────────

    #[test]
    fn run_inner_output_to_file_writes_report() {
        let dir = tmpdir();
        fs::write(dir.path().join("clean.py"), b"x=1\n").unwrap();
        let report_path = dir.path().join("report.json");
        let mut cli = make_cli(dir.path().to_path_buf());
        cli.output = Some(report_path.clone());
        let result = run_inner(&cli).unwrap();
        assert_eq!(result, ExitCode::Clean);
        assert!(report_path.exists(), "report file must be created");
    }

    // ── run_inner: SARIF format ───────────────────────────────────────────────

    #[test]
    fn run_inner_sarif_format_produces_valid_output() {
        let dir = tmpdir();
        fs::write(dir.path().join("clean.py"), b"x=1\n").unwrap();
        let mut cli = make_cli(dir.path().to_path_buf());
        cli.format = Some(OutputFormatArg::Sarif);
        let result = run_inner(&cli).unwrap();
        assert_eq!(result, ExitCode::Clean);
    }

    // ── run_inner: text format ────────────────────────────────────────────────

    #[test]
    fn run_inner_text_format_produces_output() {
        let dir = tmpdir();
        let key = "sk-xK9pQm7vL3nRwT5yJbHfDcGsEaZuViYo4W8MiNqX2Pe5AbcD";
        fs::write(dir.path().join("a.py"), format!("K='{key}'\n").as_bytes()).unwrap();
        let report_path = dir.path().join("report.txt");
        let mut cli = make_cli(dir.path().to_path_buf());
        cli.format = Some(OutputFormatArg::Text);
        cli.output = Some(report_path.clone());
        let result = run_inner(&cli).unwrap();
        assert_eq!(result, ExitCode::Findings);
        assert!(report_path.exists());
        let content = fs::read_to_string(&report_path).unwrap();
        assert!(content.contains("sf-keyaudit"), "text output must contain tool name");
    }

    // ── run_inner: suppressed finding is counted ──────────────────────────────

    #[test]
    fn run_inner_suppressed_finding_is_counted() {
        let dir = tmpdir();
        let key = "sk-xK9pQm7vL3nRwT5yJbHfDcGsEaZuViYo4W8MiNqX2Pe5AbcD";
        fs::write(dir.path().join("mock.py"), format!("KEY='{key}'\n").as_bytes()).unwrap();
        let allowlist_yaml = "allowlist:\n  - pattern_id: openai-legacy-key-v1\n    file: mock.py\n    line: 1\n    reason: \"test fixture\"\n";
        let al_path = dir.path().join(".al.yaml");
        fs::write(&al_path, allowlist_yaml.as_bytes()).unwrap();
        let mut cli = make_cli(dir.path().to_path_buf());
        cli.allowlist = Some(al_path);
        let result = run_inner(&cli).unwrap();
        assert_eq!(result, ExitCode::Clean);
    }

    // ── run_inner: oversized file triggers walk warning ───────────────────────

    #[test]
    fn run_inner_oversized_file_triggers_walk_warning() {
        let dir = tmpdir();
        let data = vec![b'x'; 500];
        fs::write(dir.path().join("big.py"), &data).unwrap();
        let mut cli = make_cli(dir.path().to_path_buf());
        cli.max_file_size = 100;
        let result = run_inner(&cli).unwrap();
        // Oversized file is skipped → no findings → Clean
        assert_eq!(result, ExitCode::Clean);
    }

    // ── run_inner: low-entropy key → low-confidence → Clean ──────────────────

    #[test]
    fn run_inner_low_entropy_key_produces_clean_exit() {
        let dir = tmpdir();
        // 48 identical chars → entropy ≈ 0 → below threshold → low_confidence
        let key = "sk-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        fs::write(dir.path().join("low.py"), format!("KEY={key}\n").as_bytes()).unwrap();
        let cli = make_cli(dir.path().to_path_buf());
        let result = run_inner(&cli).unwrap();
        assert_eq!(result, ExitCode::Clean);
    }

    // ── run_inner: expired allowlist entry ───────────────────────────────────

    #[test]
    fn run_inner_expired_allowlist_entry_emits_expired_warning() {
        let dir = tmpdir();
        let key = "sk-xK9pQm7vL3nRwT5yJbHfDcGsEaZuViYo4W8MiNqX2Pe5AbcD";
        fs::write(dir.path().join("mock.py"), format!("KEY='{key}'\n").as_bytes()).unwrap();
        let yaml = "allowlist:\n  - pattern_id: openai-legacy-key-v1\n    file: mock.py\n    line: 1\n    reason: old entry\n    expires: '2020-01-01'\n";
        let al_path = dir.path().join(".al.yaml");
        fs::write(&al_path, yaml.as_bytes()).unwrap();
        let mut cli = make_cli(dir.path().to_path_buf());
        cli.allowlist = Some(al_path);
        // Expired → finding NOT suppressed → ExitCode::Findings
        let result = run_inner(&cli).unwrap();
        assert_eq!(result, ExitCode::Findings);
    }

    // ── run_inner: unknown provider → Config error ────────────────────────────

    #[test]
    fn run_inner_unknown_provider_returns_config_error() {
        let dir = tmpdir();
        fs::write(dir.path().join("clean.py"), b"x=1\n").unwrap();
        let mut cli = make_cli(dir.path().to_path_buf());
        cli.providers = Some("bogusprovider".to_string());
        let result = run_inner(&cli);
        assert!(
            matches!(result, Err(AuditError::Config(_))),
            "unknown provider must return Config error"
        );
    }

    // ── run_inner: --threads flag ─────────────────────────────────────────────

    #[test]
    fn run_inner_threads_flag_does_not_crash() {
        let dir = tmpdir();
        fs::write(dir.path().join("clean.py"), b"x=1\n").unwrap();
        let mut cli = make_cli(dir.path().to_path_buf());
        cli.threads = Some(2);
        // Rayon's global pool may already be initialized in prior tests —
        // the error is logged as a warning; the scan must still succeed.
        let result = run_inner(&cli).unwrap();
        assert_eq!(result, ExitCode::Clean);
    }

    // ── run_inner: --generate-baseline writes a valid JSON file ──────────────

    #[test]
    fn run_inner_generate_baseline_writes_file() {
        let dir = tmpdir();
        let key = "sk-xK9pQm7vL3nRwT5yJbHfDcGsEaZuViYo4W8MiNqX2Pe5AbcD";
        fs::write(dir.path().join("keys.py"), format!("KEY='{key}'\n").as_bytes()).unwrap();
        let bl_path = dir.path().join("baseline.json");
        let mut cli = make_cli(dir.path().to_path_buf());
        cli.generate_baseline = Some(bl_path.clone());
        cli.quiet = true;
        let _ = run_inner(&cli);
        assert!(bl_path.exists(), "baseline file must be written");
        let content = fs::read_to_string(&bl_path).unwrap();
        let val: serde_json::Value =
            serde_json::from_str(&content).expect("baseline must be valid JSON");
        assert!(
            val.get("fingerprints").is_some(),
            "baseline must have 'fingerprints' field"
        );
    }

    // ── run_inner: --baseline suppresses baselined findings ───────────────────

    #[test]
    fn run_inner_baseline_suppresses_findings() {
        let dir = tmpdir();
        let key = "sk-xK9pQm7vL3nRwT5yJbHfDcGsEaZuViYo4W8MiNqX2Pe5AbcD";
        fs::write(dir.path().join("keys.py"), format!("KEY='{key}'\n").as_bytes()).unwrap();

        // Step 1: generate a baseline.
        let bl_path = dir.path().join("baseline.json");
        {
            let mut cli = make_cli(dir.path().to_path_buf());
            cli.generate_baseline = Some(bl_path.clone());
            cli.quiet = true;
            run_inner(&cli).unwrap();
        }
        assert!(bl_path.exists());

        // Step 2: re-scan with the baseline → findings must be suppressed.
        let mut cli = make_cli(dir.path().to_path_buf());
        cli.baseline = Some(bl_path);
        cli.quiet = true;
        let result = run_inner(&cli).unwrap();
        assert_eq!(result, ExitCode::Clean, "baselined findings must not trigger exit 1");
    }

    // ── run_inner: missing baseline file → Config error ───────────────────────

    #[test]
    fn run_inner_missing_baseline_file_returns_config_error() {
        let dir = tmpdir();
        fs::write(dir.path().join("clean.py"), b"x=1\n").unwrap();
        let mut cli = make_cli(dir.path().to_path_buf());
        cli.baseline = Some(dir.path().join("nonexistent_baseline.json"));
        let result = run_inner(&cli);
        assert!(matches!(result, Err(AuditError::Config(_))));
    }

    // ── run_inner: report contains metrics ────────────────────────────────────

    #[test]
    fn run_inner_report_contains_metrics() {
        let dir = tmpdir();
        fs::write(dir.path().join("clean.py"), b"x=1\n").unwrap();
        let report_path = dir.path().join("report.json");
        let mut cli = make_cli(dir.path().to_path_buf());
        cli.output = Some(report_path.clone());
        run_inner(&cli).unwrap();
        let content = fs::read_to_string(&report_path).unwrap();
        let val: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert!(val.get("metrics").is_some(), "report must have 'metrics' field");
        let duration = val["metrics"]["scan_duration_ms"].as_u64().unwrap_or(u64::MAX);
        assert!(duration < 3_600_000, "scan_duration_ms must be < 1 hour");
    }

    // ── run_inner: findings have fingerprints ─────────────────────────────────

    #[test]
    fn run_inner_findings_have_fingerprints() {
        let dir = tmpdir();
        let key = "sk-xK9pQm7vL3nRwT5yJbHfDcGsEaZuViYo4W8MiNqX2Pe5AbcD";
        fs::write(dir.path().join("a.py"), format!("K='{key}'\n").as_bytes()).unwrap();
        let report_path = dir.path().join("report.json");
        let mut cli = make_cli(dir.path().to_path_buf());
        cli.output = Some(report_path.clone());
        run_inner(&cli).unwrap();
        let content = fs::read_to_string(&report_path).unwrap();
        let val: serde_json::Value = serde_json::from_str(&content).unwrap();
        let fp = val["findings"][0]["fingerprint"]
            .as_str()
            .expect("fingerprint must be a string");
        assert!(fp.starts_with("fp-"), "fingerprint must start with fp-: {fp}");
    }

    // ── run_inner: config file auto-loads custom rules ────────────────────────

    #[test]
    fn run_inner_config_file_loads_custom_rules() {
        let dir = tmpdir();
        let config_yaml = concat!(
            "custom_rules:\n",
            "  - id: internal-token-v1\n",
            "    provider: internal\n",
            "    description: internal token\n",
            "    pattern: \"INTERNAL_TOKEN_[A-Za-z0-9]{16}\"\n",
            "    min_entropy: 2.5\n",
            "    severity: high\n",
            "    remediation: Rotate via internal portal\n",
        );
        fs::write(dir.path().join(".sfkeyaudit.yaml"), config_yaml.as_bytes()).unwrap();
        fs::write(
            dir.path().join("config.py"),
            b"token = 'INTERNAL_TOKEN_abcdef1234ABCDEF'\n",
        )
        .unwrap();
        let mut cli = make_cli(dir.path().to_path_buf());
        cli.quiet = true;
        let result = run_inner(&cli).unwrap();
        assert_eq!(
            result,
            ExitCode::Findings,
            "custom rule should detect the internal token"
        );
    }

    // ── run_inner: explicit config file not found → Config error ─────────────

    #[test]
    fn run_inner_explicit_config_not_found_returns_error() {
        let dir = tmpdir();
        fs::write(dir.path().join("clean.py"), b"x=1\n").unwrap();
        let mut cli = make_cli(dir.path().to_path_buf());
        cli.config = Some(dir.path().join("nonexistent.yaml"));
        let result = run_inner(&cli);
        assert!(matches!(result, Err(AuditError::Config(_))));
    }
}

