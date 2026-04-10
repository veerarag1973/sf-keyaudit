use thiserror::Error;

/// All errors that sf-keyaudit can produce.
#[derive(Debug, Error)]
pub enum AuditError {
    /// The scan root path does not exist or is not accessible.
    #[error("Scan root does not exist or is unreadable: {0}")]
    ScanRootInvalid(String),

    /// A fatal I/O error occurred that prevents reliable results.
    #[error("Fatal I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// The allowlist file could not be parsed.
    #[error("Allowlist file malformed: {0}")]
    AllowlistMalformed(String),

    /// An allowlist entry is missing the required `reason` field.
    #[error("Allowlist entry at {file}:{line} is missing a required `reason` field")]
    AllowlistMissingReason { file: String, line: usize },

    /// An unrecognised CLI option or invalid argument combination.
    #[error("Configuration error: {0}")]
    Config(String),

    /// A regex pattern failed to compile.
    #[error("Internal pattern compile error for '{id}': {source}")]
    PatternCompile {
        id: String,
        source: fancy_regex::Error,
    },

    /// A git command failed or git is not available.
    #[error("Git error: {0}")]
    GitError(String),

    /// JSON serialisation failed.
    #[error("Failed to serialize output: {0}")]
    Serialization(#[from] serde_json::Error),

    /// YAML parsing failed.
    #[error("Failed to parse YAML: {0}")]
    Yaml(#[from] serde_yaml::Error),

    /// Output file could not be written.
    #[error("Cannot write output file '{path}': {source}")]
    OutputWrite {
        path: String,
        source: std::io::Error,
    },

    /// Audit log could not be written or opened.
    #[error("Audit log error: {0}")]
    AuditLog(String),
}

/// Internal exit code values — stable across versions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitCode {
    /// Scan completed with zero findings.
    Clean = 0,
    /// One or more findings detected (not suppressed by allowlist).
    Findings = 1,
    /// Configuration / allowlist error; scan did not run.
    ConfigError = 2,
    /// Scan root unreadable or fatal I/O error; results unreliable.
    ScanError = 3,
    /// Scan clean but allowlist has expired or unmatched entries.
    AllowlistWarn = 4,
}

impl ExitCode {
    pub fn as_i32(self) -> i32 {
        self as i32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_codes_match_spec() {
        assert_eq!(ExitCode::Clean as i32, 0);
        assert_eq!(ExitCode::Findings as i32, 1);
        assert_eq!(ExitCode::ConfigError as i32, 2);
        assert_eq!(ExitCode::ScanError as i32, 3);
        assert_eq!(ExitCode::AllowlistWarn as i32, 4);
    }

    #[test]
    fn exit_code_as_i32_method_matches_cast() {
        assert_eq!(ExitCode::Clean.as_i32(), 0);
        assert_eq!(ExitCode::Findings.as_i32(), 1);
        assert_eq!(ExitCode::ConfigError.as_i32(), 2);
        assert_eq!(ExitCode::ScanError.as_i32(), 3);
        assert_eq!(ExitCode::AllowlistWarn.as_i32(), 4);
    }

    #[test]
    fn audit_error_display_scan_root() {
        let err = AuditError::ScanRootInvalid("/no/such/path".into());
        assert!(err.to_string().contains("/no/such/path"));
    }

    #[test]
    fn audit_error_display_allowlist_missing_reason() {
        let err = AuditError::AllowlistMissingReason {
            file: "tests/mock.py".into(),
            line: 14,
        };
        assert!(err.to_string().contains("tests/mock.py"));
        assert!(err.to_string().contains("14"));
    }

    #[test]
    fn audit_error_from_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let err: AuditError = io_err.into();
        assert!(err.to_string().contains("I/O error"));
    }
}
