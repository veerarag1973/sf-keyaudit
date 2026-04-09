use clap::Parser;
use std::path::PathBuf;

/// sf-keyaudit — scan codebases for exposed AI API keys.
///
/// Scans the working tree for credentials belonging to all major AI providers.
/// Exits 0 if clean, 1 if findings are detected.  Use in CI pipelines as a
/// hard gate before any other checks run.
#[derive(Debug, Parser)]
#[command(
    name = "sf-keyaudit",
    version,
    about = "Scans codebases for exposed AI API keys across all major providers.",
    long_about = None,
)]
pub struct Cli {
    /// Directory or file to scan.  Defaults to the current working directory.
    #[arg(value_name = "PATH")]
    pub path: Option<PathBuf>,

    /// Write the report to FILE instead of stdout.
    #[arg(short = 'o', long, value_name = "FILE")]
    pub output: Option<PathBuf>,

    /// Output format.  Default: `json` (or `default_format` from config file).
    #[arg(long, value_name = "FORMAT")]
    pub format: Option<OutputFormatArg>,

    /// Stop on the first finding instead of scanning all files.
    #[arg(long)]
    pub fail_fast: bool,

    /// Disable .gitignore and .sfignore exclusions — scan everything.
    #[arg(long)]
    pub no_ignore: bool,

    /// Path to a gitignore-style ignore file.  Repeatable.
    ///
    /// Each value must be a path to an ignore file (gitignore format).
    /// Every pattern inside that file will be applied during the walk.
    /// Example: --ignore-file .myignore
    #[arg(long = "ignore-file", value_name = "FILE", action = clap::ArgAction::Append)]
    pub ignore_file: Vec<String>,

    /// Skip files larger than BYTES.  Default: 10485760 (10 MiB).
    #[arg(long, value_name = "BYTES", default_value_t = 10 * 1024 * 1024)]
    pub max_file_size: u64,

    /// Maximum directory traversal depth.  Default: unlimited.
    #[arg(long, value_name = "N")]
    pub max_depth: Option<usize>,

    /// Comma-separated list of providers to scan for.  Default: all.
    ///
    /// Example: --providers openai,anthropic,google
    #[arg(long, value_name = "LIST")]
    pub providers: Option<String>,

    /// Path to an allowlist YAML file (.sfkeyaudit-allow.yaml).
    #[arg(long, value_name = "FILE")]
    pub allowlist: Option<PathBuf>,

    /// Follow symbolic links during directory traversal.  Off by default to
    /// prevent scanning outside the intended tree.
    #[arg(long)]
    pub follow_links: bool,

    /// Suppress all stdout output.  Exit code is the only signal.
    #[arg(short = 'q', long)]
    pub quiet: bool,

    /// Print each file path as it is scanned.
    #[arg(short = 'v', long)]
    pub verbose: bool,

    /// Path to a project configuration file (`.sfkeyaudit.yaml`).
    /// If omitted, sf-keyaudit searches for the config file starting from PATH
    /// and walking up to the filesystem root.
    #[arg(long, value_name = "FILE")]
    pub config: Option<PathBuf>,

    /// Number of parallel scan threads.  Default: number of logical CPU cores.
    #[arg(long, value_name = "N")]
    pub threads: Option<usize>,

    /// After scanning, write a baseline file to FILE containing the fingerprints
    /// of all high-confidence findings.  Use `--baseline` in subsequent runs to
    /// suppress these findings.
    #[arg(long, value_name = "FILE")]
    pub generate_baseline: Option<PathBuf>,

    /// Compare findings against a previously generated baseline file.
    /// Findings whose fingerprints appear in the baseline are moved to
    /// `baselined_findings` and do not trigger a non-zero exit code.
    #[arg(long, value_name = "FILE")]
    pub baseline: Option<PathBuf>,

    /// Scan only files that have been staged for commit (`git diff --staged`).
    /// Requires the scan path to be inside a git repository.
    #[arg(long, conflicts_with = "diff_base")]
    pub staged: bool,

    /// Scan only files changed since GIT_REF (`git diff <GIT_REF>`).
    /// Requires the scan path to be inside a git repository.
    /// Conflicts with `--staged`.
    #[arg(long, value_name = "GIT_REF", conflicts_with = "staged")]
    pub diff_base: Option<String>,

    /// Scan all files changed between COMMIT_REF and HEAD.
    ///
    /// Useful for scanning a whole PR branch: `--since-commit origin/main`.
    /// Conflicts with `--staged` and `--diff-base`.
    #[arg(
        long,
        value_name = "COMMIT_REF",
        conflicts_with_all = &["staged", "diff_base"]
    )]
    pub since_commit: Option<String>,

    /// Scan every file ever touched in the full git history (all branches).
    ///
    /// WARNING: may be very slow on large repos.  Conflicts with `--staged`,
    /// `--diff-base`, and `--since-commit`.
    #[arg(
        long,
        conflicts_with_all = &["staged", "diff_base", "since_commit"]
    )]
    pub history: bool,

    /// Apply offline heuristic validation to each finding and annotate its
    /// `validation_status` field ("likely-valid", "test-key", etc.).
    #[arg(long)]
    pub verify: bool,

    /// Group output by the specified field.
    ///
    /// Valid values: `file`, `provider`, `severity`.
    /// Only affects `--format text` output.
    #[arg(long, value_name = "FIELD")]
    pub group_by: Option<GroupByArg>,

    /// Enrich findings with CODEOWNERS matches and git-blame author information.
    ///
    /// Requires the scan path to be inside a git repository that has a
    /// CODEOWNERS file.
    #[arg(long)]
    pub owners: bool,

    /// Also scan inside zip and tar/tgz archives found during the walk.
    #[arg(long)]
    pub scan_archives: bool,

    /// Load and save a hash-based scan cache to FILE.  Files whose content
    /// hash matches the cache are skipped, dramatically speeding up repeated
    /// scans over large, mostly-unchanged trees.
    #[arg(long, value_name = "FILE")]
    pub cache_file: Option<PathBuf>,

    /// Remove stale entries from the baseline before writing it.  A stale
    /// entry is one whose fingerprint no longer appears in the current scan
    /// results.  Requires `--generate-baseline`.
    #[arg(long, requires = "generate_baseline")]
    pub prune_baseline: bool,

    /// Record who approved the baseline.  Sets `approved_by` and `approved_at`
    /// on every entry in the generated baseline file.  Requires
    /// `--generate-baseline`.  Can also be supplied via the
    /// `SFKEYAUDIT_APPROVED_BY` environment variable.
    #[arg(long, value_name = "NAME", requires = "generate_baseline")]
    pub baseline_approved_by: Option<String>,

    /// Subcommand (e.g. `install-hooks`).
    #[command(subcommand)]
    pub command: Option<SfSubcommand>,
}

/// Accepted values for the `--group-by` argument.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum GroupByArg {
    File,
    Provider,
    Severity,
}

/// Accepted values for the `--format` argument.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum OutputFormatArg {
    Json,
    Sarif,
    Text,
}

/// Subcommands for sf-keyaudit.
#[derive(Debug, clap::Subcommand)]
pub enum SfSubcommand {
    /// Install sf-keyaudit git hooks (pre-commit and pre-push).
    ///
    /// Installs hook scripts into `.git/hooks/` so that every commit and push
    /// is automatically scanned for exposed credentials.
    InstallHooks {
        /// Repository root to install hooks into (defaults to the current directory).
        path: Option<PathBuf>,
        /// Overwrite existing hooks without prompting.
        #[arg(long)]
        force: bool,
    },
}

impl Cli {
    /// Parse the provider filter from `--providers` into a `Vec<String>`.
    pub fn provider_list(&self) -> Vec<String> {
        match &self.providers {
            None => vec![],
            Some(s) => s
                .split(',')
                .map(|p| p.trim().to_lowercase())
                .filter(|p| !p.is_empty())
                .collect(),
        }
    }
}

impl From<OutputFormatArg> for crate::types::OutputFormat {
    fn from(a: OutputFormatArg) -> Self {
        match a {
            OutputFormatArg::Json => crate::types::OutputFormat::Json,
            OutputFormatArg::Sarif => crate::types::OutputFormat::Sarif,
            OutputFormatArg::Text => crate::types::OutputFormat::Text,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Cli {
        Cli::try_parse_from(std::iter::once("sf-keyaudit").chain(args.iter().copied()))
            .unwrap_or_else(|e| panic!("failed to parse args: {e}"))
    }

    #[test]
    fn default_path_is_none() {
        let cli = parse(&[]);
        assert!(cli.path.is_none());
    }

    #[test]
    fn explicit_path_set() {
        let cli = parse(&["./src"]);
        assert_eq!(cli.path, Some(PathBuf::from("./src")));
    }

    #[test]
    fn output_flag() {
        let cli = parse(&["--output", "report.json"]);
        assert_eq!(cli.output, Some(PathBuf::from("report.json")));
    }

    #[test]
    fn format_defaults_to_json() {
        let cli = parse(&[]);
        assert_eq!(cli.format, None);
    }

    #[test]
    fn format_sarif() {
        let cli = parse(&["--format", "sarif"]);
        assert_eq!(cli.format, Some(OutputFormatArg::Sarif));
    }

    #[test]
    fn fail_fast_flag() {
        let cli = parse(&["--fail-fast"]);
        assert!(cli.fail_fast);
    }

    #[test]
    fn no_ignore_flag() {
        let cli = parse(&["--no-ignore"]);
        assert!(cli.no_ignore);
    }

    #[test]
    fn quiet_short_flag() {
        let cli = parse(&["-q"]);
        assert!(cli.quiet);
    }

    #[test]
    fn verbose_short_flag() {
        let cli = parse(&["-v"]);
        assert!(cli.verbose);
    }

    #[test]
    fn max_file_size_default() {
        let cli = parse(&[]);
        assert_eq!(cli.max_file_size, 10 * 1024 * 1024);
    }

    #[test]
    fn max_file_size_custom() {
        let cli = parse(&["--max-file-size", "5000"]);
        assert_eq!(cli.max_file_size, 5000);
    }

    #[test]
    fn max_depth_default_is_none() {
        let cli = parse(&[]);
        assert!(cli.max_depth.is_none());
    }

    #[test]
    fn max_depth_custom() {
        let cli = parse(&["--max-depth", "3"]);
        assert_eq!(cli.max_depth, Some(3));
    }

    #[test]
    fn providers_flag_parses_list() {
        let cli = parse(&["--providers", "openai,anthropic,google"]);
        let list = cli.provider_list();
        assert_eq!(list, vec!["openai", "anthropic", "google"]);
    }

    #[test]
    fn providers_empty_returns_empty_vec() {
        let cli = parse(&[]);
        assert!(cli.provider_list().is_empty());
    }

    #[test]
    fn providers_trims_whitespace() {
        let cli = parse(&["--providers", " openai , anthropic "]);
        let list = cli.provider_list();
        assert_eq!(list, vec!["openai", "anthropic"]);
    }

    #[test]
    fn allowlist_flag() {
        let cli = parse(&["--allowlist", ".sfkeyaudit-allow.yaml"]);
        assert_eq!(cli.allowlist, Some(PathBuf::from(".sfkeyaudit-allow.yaml")));
    }

    #[test]
    fn ignore_file_repeatable() {
        let cli = parse(&["--ignore-file", "my.gitignore", "--ignore-file", ".extra_ignore"]);
        assert_eq!(cli.ignore_file, vec!["my.gitignore", ".extra_ignore"]);
    }

    #[test]
    fn output_format_converts_to_type() {
        use crate::types::OutputFormat;
        assert_eq!(OutputFormat::from(OutputFormatArg::Json), OutputFormat::Json);
        assert_eq!(OutputFormat::from(OutputFormatArg::Sarif), OutputFormat::Sarif);
        assert_eq!(OutputFormat::from(OutputFormatArg::Text), OutputFormat::Text);
    }

    #[test]
    fn format_text() {
        let cli = parse(&["--format", "text"]);
        assert_eq!(cli.format, Some(OutputFormatArg::Text));
    }

    #[test]
    fn threads_flag() {
        let cli = parse(&["--threads", "4"]);
        assert_eq!(cli.threads, Some(4));
    }

    #[test]
    fn threads_default_is_none() {
        let cli = parse(&[]);
        assert!(cli.threads.is_none());
    }

    #[test]
    fn generate_baseline_flag() {
        let cli = parse(&["--generate-baseline", "baseline.json"]);
        assert_eq!(cli.generate_baseline, Some(PathBuf::from("baseline.json")));
    }

    #[test]
    fn baseline_flag() {
        let cli = parse(&["--baseline", "baseline.json"]);
        assert_eq!(cli.baseline, Some(PathBuf::from("baseline.json")));
    }

    #[test]
    fn staged_flag() {
        let cli = parse(&["--staged"]);
        assert!(cli.staged);
    }

    #[test]
    fn diff_base_flag() {
        let cli = parse(&["--diff-base", "main"]);
        assert_eq!(cli.diff_base, Some("main".to_string()));
    }

    #[test]
    fn staged_and_diff_base_conflict() {
        // clap should reject --staged with --diff-base
        let result = Cli::try_parse_from(["sf-keyaudit", "--staged", "--diff-base", "main"]);
        assert!(result.is_err(), "staged and diff-base should conflict");
    }

    #[test]
    fn config_flag() {
        let cli = parse(&["--config", "custom.yaml"]);
        assert_eq!(cli.config, Some(PathBuf::from("custom.yaml")));
    }
}
