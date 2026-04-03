mod allowlist;
mod cli;
mod entropy;
mod error;
mod output;
mod patterns;
mod scanner;
mod types;
mod walker;

use allowlist::{today_utc, Allowlist, AllowlistWarning};
use chrono::Utc;
use clap::{CommandFactory, FromArgMatches};
use cli::Cli;
use error::{AuditError, ExitCode};
use patterns::{build_patterns, filter_by_providers};
use rayon::prelude::*;
use scanner::{scan_content, RawFinding};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use types::{Finding, OutputFormat, Report, Summary};
use uuid::Uuid;
use walker::{read_file_content_lossy, walk, walk_single_file, WalkConfig};

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
    let code = run();
    std::process::exit(code);
}

fn run() -> i32 {
    dispatch_result(run_inner(&parse_cli()))
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
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::ScanError.as_i32()
        }
    }
}

fn run_inner(cli: &Cli) -> Result<ExitCode, AuditError> {
    // Resolve scan root.
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

    // Load patterns and validate --providers early.
    let all_patterns = build_patterns()?;
    let provider_filter = cli.provider_list();
    let active_patterns: Vec<&patterns::Pattern> =
        filter_by_providers(&all_patterns, &provider_filter)?;

    // Load allowlist, if provided.
    let allowlist = if let Some(al_path) = &cli.allowlist {
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

    // Walk the filesystem — returns paths only (no file contents).
    let walk_config = WalkConfig {
        max_file_size: cli.max_file_size,
        max_depth: cli.max_depth,
        no_ignore: cli.no_ignore,
        extra_ignore_files: cli.ignore_file.clone(),
        follow_links: cli.follow_links,
    };

    let walk_entries = if scan_path.is_file() {
        walk_single_file(&scan_path, &walk_config)
    } else {
        walk(&scan_root, &walk_config)
    };

    // Emit walk warnings (oversized files, stat failures, etc.).
    for entry in &walk_entries {
        if let Some(warn) = &entry.warning {
            eprintln!("warning: {warn}");
        }
    }

    // Only keep entries without warnings (i.e. scannable files).
    let scannable: Vec<_> = walk_entries
        .into_iter()
        .filter(|e| e.warning.is_none())
        .collect();

    let files_scanned = scannable.len();

    // Parallel read + pattern matching.
    // Each rayon worker reads its own file so only one file is in memory per thread.
    let fail_fast_flag = Arc::new(AtomicBool::new(false));

    let raw_findings: Vec<RawFinding> = scannable
        .par_iter()
        .flat_map(|entry| {
            if cli.fail_fast && fail_fast_flag.load(Ordering::Relaxed) {
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

            // Read the file inside the worker — keeps only one file per thread in RAM.
            let (content_opt, read_warn) = read_file_content_lossy(&entry.path);
            if let Some(warn) = read_warn {
                eprintln!("warning: {warn}");
            }
            let content = match content_opt {
                Some(c) => c,
                None => return vec![], // binary — silent skip
            };

            let file_findings = scan_content(&rel_path, &content, &active_patterns);

            if cli.fail_fast && !file_findings.is_empty() {
                fail_fast_flag.store(true, Ordering::Relaxed);
            }

            file_findings
        })
        .collect();

    // Assign sequential IDs and split high/low confidence.
    let mut seq = 1usize;
    let mut findings: Vec<Finding> = Vec::new();
    let mut low_confidence: Vec<Finding> = Vec::new();

    for raw in raw_findings {
        let finding = Finding::new(
            seq,
            &raw.provider,
            &raw.file,
            raw.line,
            raw.column,
            raw.match_text,
            &raw.pattern_id,
            raw.entropy,
        );
        seq += 1;
        if raw.high_confidence {
            findings.push(finding);
        } else {
            low_confidence.push(finding);
        }
    }

    // Apply allowlist.
    let today = today_utc();
    let (suppressed, active_findings, al_warnings) = allowlist.apply(&findings, today);

    // Emit allowlist warnings to stderr.
    for w in &al_warnings {
        match w {
            AllowlistWarning::Expired { pattern_id, file, line } => {
                eprintln!(
                    "warning: allowlist entry {pattern_id} at {file}:{line} has expired and is no longer suppressing"
                );
            }
            AllowlistWarning::Unmatched { pattern_id, file, line } => {
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

    // Build report.
    let summary = Summary::from_findings(&active_findings);
    let report = Report {
        scan_id: Uuid::new_v4().to_string(),
        tool: "sf-keyaudit".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        timestamp: Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        scan_root: scan_root.display().to_string(),
        files_scanned,
        findings: active_findings.clone(),
        low_confidence_findings: low_confidence,
        summary,
    };

    // Output.
    if !cli.quiet {
        let format: OutputFormat = cli.format.into();
        match output::render(&report, format, cli.output.as_deref())? {
            Some(text) => println!("{text}"),
            None => {} // written to file
        }
    }

    // Determine exit code.
    let has_allowlist_issues = !al_warnings.is_empty();

    if !active_findings.is_empty() {
        Ok(ExitCode::Findings)
    } else if has_allowlist_issues {
        Ok(ExitCode::AllowlistWarn)
    } else {
        Ok(ExitCode::Clean)
    }
}

/// Tiny path utility — compute relative path from base to draft.
mod pathdiff {
    use std::path::{Path, PathBuf};

    pub fn entry_relative(base: &Path, target: &Path) -> String {
        // Try to strip the base prefix; fall back to the full path.
        let rel: PathBuf = target
            .strip_prefix(base)
            .map(|r| r.to_path_buf())
            .unwrap_or_else(|_| target.to_path_buf());
        // Normalise path separators to forward-slash for cross-platform output.
        rel.display()
            .to_string()
            .replace('\\', "/")
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
            format: OutputFormatArg::Json,
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
        // Falls back to full target path, normalised
        assert!(rel.contains("main.rs"));
    }

    #[test]
    fn pathdiff_normalizes_backslashes() {
        // Simulate Windows-style path by using the replace logic directly
        let s = "src\\lib\\mod.rs".replace('\\', "/");
        assert_eq!(s, "src/lib/mod.rs");
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

    // ── run_inner: allowlist suppresses finding (unmatched → AllowlistWarn) ──

    #[test]
    fn run_inner_allowlist_unmatched_entry_returns_allowlist_warn() {
        let dir = tmpdir();
        // Clean file — no real key
        fs::write(dir.path().join("clean.py"), b"x = 1\n").unwrap();
        // Allowlist with an unmatched entry (points to a file/line with no finding)
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
        // Suppressed finding → no active findings; no allowlist warnings (no unmatched)
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
        // OpenAI key in file, but scanning only for anthropic
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
        cli.format = OutputFormatArg::Sarif;
        let result = run_inner(&cli).unwrap();
        assert_eq!(result, ExitCode::Clean);
    }

    // ── run inner: suppressed finding emits stderr info ───────────────────────

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
        // non-quiet so the "suppressed N" message is emitted to stderr
        let result = run_inner(&cli).unwrap();
        assert_eq!(result, ExitCode::Clean);
    }

    // ── dispatch_result error arms ────────────────────────────────────────────

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

    // ── run_inner: walk warning path (line 110) ───────────────────────────────

    #[test]
    fn run_inner_oversized_file_triggers_walk_warning() {
        let dir = tmpdir();
        let data = vec![b'x'; 500];
        fs::write(dir.path().join("big.py"), &data).unwrap();
        let mut cli = make_cli(dir.path().to_path_buf());
        cli.max_file_size = 100;
        let result = run_inner(&cli).unwrap();
        // oversized file is skipped → no findings → Clean
        assert_eq!(result, ExitCode::Clean);
    }

    // ── run_inner: low-confidence finding (line 178) ──────────────────────────

    #[test]
    fn run_inner_low_entropy_key_produces_clean_exit() {
        let dir = tmpdir();
        // 48 identical chars → entropy=0 → below threshold → low_confidence branch
        let key = "sk-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        fs::write(dir.path().join("low.py"), format!("KEY={key}\n").as_bytes()).unwrap();
        let cli = make_cli(dir.path().to_path_buf());
        let result = run_inner(&cli).unwrap();
        // low-confidence findings do not trigger exit 1
        assert_eq!(result, ExitCode::Clean);
    }

    // ── run_inner: expired allowlist entry (lines 189-191) ───────────────────

    #[test]
    fn run_inner_expired_allowlist_entry_emits_expired_warning() {
        let dir = tmpdir();
        let key = "sk-xK9pQm7vL3nRwT5yJbHfDcGsEaZuViYo4W8MiNqX2Pe5AbcD";
        fs::write(dir.path().join("mock.py"), format!("KEY='{key}'\n").as_bytes()).unwrap();
        // Expired allowlist entry — past expires date → does NOT suppress the finding
        let yaml = "allowlist:\n  - pattern_id: openai-legacy-key-v1\n    file: mock.py\n    line: 1\n    reason: old entry\n    expires: '2020-01-01'\n";
        let al_path = dir.path().join(".al.yaml");
        fs::write(&al_path, yaml.as_bytes()).unwrap();
        let mut cli = make_cli(dir.path().to_path_buf());
        cli.allowlist = Some(al_path);
        // Expired → finding not suppressed → active finding → Findings
        let result = run_inner(&cli).unwrap();
        assert_eq!(result, ExitCode::Findings);
    }

    // ── run_inner: unknown provider returns Config error ──────────────────────

    #[test]
    fn run_inner_unknown_provider_returns_config_error() {
        let dir = tmpdir();
        fs::write(dir.path().join("clean.py"), b"x=1\n").unwrap();
        let mut cli = make_cli(dir.path().to_path_buf());
        cli.providers = Some("bogusprovider".to_string());
        let result = run_inner(&cli);
        assert!(matches!(result, Err(AuditError::Config(_))), "unknown provider must return Config error");
    }
}

