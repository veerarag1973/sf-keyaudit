//! Project-level configuration file (.sfkeyaudit.yaml).
//!
//! When `--config` is not passed, the tool auto-discovers `.sfkeyaudit.yaml`
//! by walking up from the scan root toward the filesystem root.  All fields
//! are optional; absent fields fall back to CLI defaults or built-in defaults.

use crate::error::AuditError;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

/// Top-level project configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProjectConfig {
    /// Providers to scan for (overridden by `--providers`).
    pub providers: Option<Vec<String>>,
    /// Maximum file size in bytes (overridden by `--max-file-size`).
    pub max_file_size: Option<u64>,
    /// Maximum traversal depth (overridden by `--max-depth`).
    pub max_depth: Option<usize>,
    /// Number of rayon threads (0 = Rayon default = logical CPUs).
    #[serde(default)]
    pub threads: usize,
    /// Extra gitignore-style patterns applied to every scan.
    #[serde(default)]
    pub ignore_patterns: Vec<String>,
    /// Gitignore-style patterns that whitelist files for scanning.
    /// When non-empty, only files matching at least one pattern are scanned.
    #[serde(default)]
    pub include_patterns: Vec<String>,
    /// Custom rules added on top of the built-in provider patterns.
    #[serde(default)]
    pub custom_rules: Vec<CustomRuleDef>,
    /// Per-pattern-ID severity overrides (e.g. `{"pinecone-api-key-v1": "critical"}`).
    #[serde(default)]
    pub severity_overrides: HashMap<String, String>,
    /// Default output format when `--format` is not passed on the CLI.
    /// Accepted values: `"json"`, `"sarif"`, `"text"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_format: Option<String>,
    /// Override the minimum Shannon entropy threshold for all built-in patterns.
    /// Lower values detect more (with potentially more false positives).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_entropy_override: Option<f64>,
    /// Path to the allowlist YAML file (overridden by `--allowlist`).
    /// Relative paths are resolved from the config file's directory.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowlist: Option<std::path::PathBuf>,
    /// Path to the baseline JSON file (overridden by `--baseline`).
    /// Relative paths are resolved from the config file's directory.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub baseline: Option<std::path::PathBuf>,
    /// Default output file path (overridden by `--output`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_file: Option<std::path::PathBuf>,
    /// Stop on the first finding (overridden by `--fail-fast`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fail_fast: Option<bool>,
}

/// A user-defined custom detection rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomRuleDef {
    /// Stable pattern ID following the `{provider}-{type}-v{N}` convention.
    pub id: String,
    /// Provider slug used in findings, e.g. `my-company`.
    pub provider: String,
    /// Human-readable description (optional).
    pub description: Option<String>,
    /// Regex containing a named group `(?P<body>...)`.
    /// Optional `(?P<prefix>...)` is preserved in redacted output.
    pub pattern: String,
    /// Minimum Shannon entropy for high-confidence classification.
    /// Defaults to 3.5 when omitted.
    pub min_entropy: Option<f64>,
    /// Severity: `"critical"`, `"high"`, or `"medium"`.
    /// Defaults to `"high"` when omitted.
    pub severity: Option<String>,
    /// Remediation guidance shown in text/JSON/SARIF output.
    pub remediation: Option<String>,
}

impl ProjectConfig {
    /// Load from a YAML file at `path`.  Returns `None` if the file does not exist.
    pub fn load(path: &Path) -> Result<Option<Self>, AuditError> {
        if !path.exists() {
            return Ok(None);
        }
        let content = std::fs::read_to_string(path).map_err(|e| {
            AuditError::Config(format!(
                "cannot read config file {}: {e}",
                path.display()
            ))
        })?;
        let config: Self = serde_yaml::from_str(&content).map_err(|e| {
            AuditError::Config(format!(
                "malformed config file {}: {e}",
                path.display()
            ))
        })?;
        Ok(Some(config))
    }

    /// Walk up from `start` looking for `.sfkeyaudit.yaml`.
    /// Returns `None` if no config file is found.
    pub fn find_and_load(start: &Path) -> Result<Option<Self>, AuditError> {
        let mut dir = if start.is_file() {
            start
                .parent()
                .map(|p| p.to_path_buf())
                .unwrap_or_else(|| std::path::PathBuf::from("."))
        } else {
            start.to_path_buf()
        };
        loop {
            let candidate = dir.join(".sfkeyaudit.yaml");
            if candidate.exists() {
                tracing::debug!(path = %candidate.display(), "loaded project config");
                return Self::load(&candidate);
            }
            match dir.parent() {
                Some(p) => dir = p.to_path_buf(),
                None => return Ok(None),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn tmpdir() -> TempDir {
        tempfile::tempdir().unwrap()
    }

    #[test]
    fn load_returns_none_for_missing_file() {
        let result = ProjectConfig::load(std::path::Path::new("/no/such/file.yaml")).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn load_parses_minimal_config() {
        let dir = tmpdir();
        let yaml = "providers:\n  - openai\nthreads: 4\n";
        fs::write(dir.path().join(".sfkeyaudit.yaml"), yaml).unwrap();
        let cfg = ProjectConfig::load(&dir.path().join(".sfkeyaudit.yaml"))
            .unwrap()
            .unwrap();
        assert_eq!(cfg.providers, Some(vec!["openai".to_string()]));
        assert_eq!(cfg.threads, 4);
    }

    #[test]
    fn load_parses_custom_rules() {
        let dir = tmpdir();
        let yaml = r#"
custom_rules:
  - id: internal-token-v1
    provider: my-company
    description: "Internal auth token"
    pattern: "(?P<prefix>myco-)(?P<body>[A-Za-z0-9]{32})"
    min_entropy: 3.5
    severity: critical
    remediation: "Rotate via https://internal.example.com"
"#;
        fs::write(dir.path().join(".sfkeyaudit.yaml"), yaml).unwrap();
        let cfg = ProjectConfig::load(&dir.path().join(".sfkeyaudit.yaml"))
            .unwrap()
            .unwrap();
        assert_eq!(cfg.custom_rules.len(), 1);
        assert_eq!(cfg.custom_rules[0].id, "internal-token-v1");
        assert_eq!(cfg.custom_rules[0].severity, Some("critical".to_string()));
        assert!(cfg.custom_rules[0].remediation.is_some());
    }

    #[test]
    fn find_and_load_discovers_config_in_parent() {
        let parent = tmpdir();
        let child = parent.path().join("sub");
        fs::create_dir(&child).unwrap();
        let yaml = "threads: 2\n";
        fs::write(parent.path().join(".sfkeyaudit.yaml"), yaml).unwrap();
        let cfg = ProjectConfig::find_and_load(&child).unwrap().unwrap();
        assert_eq!(cfg.threads, 2);
    }

    #[test]
    fn find_and_load_returns_none_when_not_found() {
        // Use a temp dir that definitely has no .sfkeyaudit.yaml in its ancestry
        // (not guaranteed in a repo, so we scan a known temp dir directly)
        let dir = tmpdir();
        // No .sfkeyaudit.yaml written — should return None
        let result = ProjectConfig::find_and_load(dir.path()).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn severity_overrides_parsed() {
        let dir = tmpdir();
        let yaml = "severity_overrides:\n  pinecone-api-key-v1: critical\n";
        fs::write(dir.path().join(".sfkeyaudit.yaml"), yaml).unwrap();
        let cfg = ProjectConfig::load(&dir.path().join(".sfkeyaudit.yaml"))
            .unwrap()
            .unwrap();
        assert_eq!(
            cfg.severity_overrides.get("pinecone-api-key-v1").map(|s| s.as_str()),
            Some("critical")
        );
    }
}
