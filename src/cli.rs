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

    /// Output format.
    #[arg(long, value_name = "FORMAT", default_value = "json")]
    pub format: OutputFormatArg,

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
}

/// Accepted values for the `--format` argument.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum OutputFormatArg {
    Json,
    Sarif,
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
        assert_eq!(cli.format, OutputFormatArg::Json);
    }

    #[test]
    fn format_sarif() {
        let cli = parse(&["--format", "sarif"]);
        assert_eq!(cli.format, OutputFormatArg::Sarif);
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
    }
}
