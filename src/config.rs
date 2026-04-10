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
    /// Directories containing plugin YAML files (each file is a list of
    /// `CustomRuleDef` entries).  Paths are resolved relative to the config
    /// file's parent directory.
    #[serde(default)]
    pub plugin_dirs: Vec<std::path::PathBuf>,
    /// Declarative network validators for custom or unsupported providers.
    /// See [`crate::verify::CustomValidatorDef`] for the schema.
    #[serde(default)]
    pub custom_validators: Vec<crate::verify::CustomValidatorDef>,
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
    /// Policy enforcement configuration (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy: Option<PolicyConfig>,
}

// ── Policy configuration ───────────────────────────────────────────────────────

/// Named, built-in policy packs that can be selected by the `--policy-pack`
/// flag or the `policy.pack` config key.  Each pack is a pre-canned set of
/// thresholds and enforcement rules adapted for a common deployment context.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum PolicyPackName {
    /// Strict gate suitable for automated CI — blocks on any critical/high
    /// finding that is not suppressed.
    StrictCi,
    /// More permissive gate suited for local developer workflows — only blocks
    /// on critical findings.
    #[default]
    DeveloperFriendly,
    /// Default for enterprise deployments — blocks on critical findings,
    /// requires owner annotation for high-severity findings.
    EnterpriseDefault,
    /// Tight gate for regulated environments — blocks on critical *and* high
    /// findings with a mandatory audit log rotation policy.
    RegulatedEnv,
    /// No built-in pack; all policy is configured explicitly via the `policy`
    /// section in the config file.
    Custom,
}

impl PolicyPackName {
    /// Return the `&str` slug used in config files and CLI arguments.
    pub fn as_str(&self) -> &'static str {
        match self {
            PolicyPackName::StrictCi => "strict-ci",
            PolicyPackName::DeveloperFriendly => "developer-friendly",
            PolicyPackName::EnterpriseDefault => "enterprise-default",
            PolicyPackName::RegulatedEnv => "regulated-env",
            PolicyPackName::Custom => "custom",
        }
    }
}

impl std::fmt::Display for PolicyPackName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for PolicyPackName {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "strict-ci" => Ok(PolicyPackName::StrictCi),
            "developer-friendly" => Ok(PolicyPackName::DeveloperFriendly),
            "enterprise-default" => Ok(PolicyPackName::EnterpriseDefault),
            "regulated-env" => Ok(PolicyPackName::RegulatedEnv),
            "custom" => Ok(PolicyPackName::Custom),
            other => Err(format!(
                "unknown policy pack '{other}'; valid values: strict-ci, developer-friendly, enterprise-default, regulated-env, custom"
            )),
        }
    }
}

/// Policy enforcement settings.  When a `pack` other than `Custom` is chosen,
/// these fields act as *overrides* on top of the pack defaults.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PolicyConfig {
    /// Select a built-in policy pack (default: `developer-friendly`).
    #[serde(default)]
    pub pack: PolicyPackName,

    /// Minimum severity level that causes a non-zero exit code.
    /// Accepted values: `"critical"`, `"high"`, `"medium"`.
    /// When `None`, the pack default is used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_severity_to_fail: Option<String>,

    /// Whether to block when network validation confirms a live credential.
    /// `false` → emit a finding but still exit 0.
    #[serde(default = "default_true")]
    pub block_on_confirmed_live: bool,

    /// Maximum number of allowed suppression entries before the policy
    /// considers the suppression list stale.  `None` = no limit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_suppressions: Option<usize>,

    /// How many days a suppression entry is valid before it must be renewed.
    /// `None` = suppressions never expire.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suppression_expiration_days: Option<u64>,

    /// When `true`, every high/critical finding must have an `owner` field
    /// (populated from `--owner` or `ownership.rs` git-blame lookup).
    #[serde(default)]
    pub require_owner: bool,

    /// Extra per-pattern-ID rules that take priority over pack defaults.
    /// Key: pattern ID (e.g. `"openai-key-v1"`).
    /// Value: `"block"` | `"warn"` | `"allow"`.
    #[serde(default)]
    pub rule_overrides: HashMap<String, String>,

    /// Minimum confidence tier for a finding to be considered by policy rules.
    ///
    /// When set, findings whose `confidence` is *below* this tier are
    /// unconditionally allowed (skipped) by policy evaluation.  This is the
    /// primary adoption lever for teams wanting to roll out policy enforcement
    /// gradually: start with `high` (structured, low-FP patterns only) and
    /// lower the threshold over time.
    ///
    /// Findings with unknown confidence (`None`) are always evaluated
    /// regardless of this setting — we err on the side of caution.
    ///
    /// Accepted values: `"high"`, `"medium"`, `"low"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence_min: Option<crate::patterns::ConfidenceTier>,
}

fn default_true() -> bool { true }

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

/// Load plugin rule files from a list of directories.
///
/// Each directory is scanned for `*.yaml` and `*.yml` files.  Every file must
/// contain a YAML list of [`CustomRuleDef`] entries.  Invalid files are logged
/// and skipped.
pub fn load_plugin_rules(dirs: &[std::path::PathBuf]) -> Result<Vec<CustomRuleDef>, AuditError> {
    let mut rules = Vec::new();
    for dir in dirs {
        if !dir.is_dir() {
            tracing::warn!(path = %dir.display(), "plugin directory does not exist; skipping");
            continue;
        }
        let entries = std::fs::read_dir(dir).map_err(|e| {
            AuditError::Config(format!("cannot read plugin directory {}: {e}", dir.display()))
        })?;
        for entry in entries {
            let entry = entry.map_err(|e| {
                AuditError::Config(format!("error reading plugin directory entry: {e}"))
            })?;
            let path = entry.path();
            let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
            if ext != "yaml" && ext != "yml" {
                continue;
            }
            let content = std::fs::read_to_string(&path).map_err(|e| {
                AuditError::Config(format!("cannot read plugin file {}: {e}", path.display()))
            })?;
            match serde_yaml::from_str::<Vec<CustomRuleDef>>(&content) {
                Ok(defs) => {
                    tracing::info!(
                        path = %path.display(),
                        count = defs.len(),
                        "loaded plugin rules"
                    );
                    rules.extend(defs);
                }
                Err(e) => {
                    tracing::warn!(
                        path = %path.display(),
                        error = %e,
                        "skipping malformed plugin file"
                    );
                }
            }
        }
    }
    Ok(rules)
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

    // ── PolicyPackName ─────────────────────────────────────────────────────────

    #[test]
    fn policy_pack_name_from_str_roundtrips() {
        use std::str::FromStr;
        let variants = [
            ("strict-ci",          PolicyPackName::StrictCi),
            ("developer-friendly", PolicyPackName::DeveloperFriendly),
            ("enterprise-default", PolicyPackName::EnterpriseDefault),
            ("regulated-env",      PolicyPackName::RegulatedEnv),
            ("custom",             PolicyPackName::Custom),
        ];
        for (slug, expected) in variants {
            let parsed = PolicyPackName::from_str(slug).unwrap();
            assert_eq!(parsed, expected, "failed for slug '{slug}'");
            assert_eq!(parsed.as_str(), slug, "as_str roundtrip failed for '{slug}'");
        }
    }

    #[test]
    fn policy_pack_name_from_str_unknown_returns_error() {
        use std::str::FromStr;
        assert!(PolicyPackName::from_str("nonexistent").is_err());
    }

    #[test]
    fn policy_pack_name_display() {
        assert_eq!(format!("{}", PolicyPackName::StrictCi), "strict-ci");
        assert_eq!(format!("{}", PolicyPackName::RegulatedEnv), "regulated-env");
    }

    // ── PolicyConfig in YAML ───────────────────────────────────────────────────

    #[test]
    fn load_parses_policy_config_from_yaml() {
        let dir = tmpdir();
        let yaml = "policy:\n  pack: strict_ci\n  require_owner: true\n";
        fs::write(dir.path().join(".sfkeyaudit.yaml"), yaml).unwrap();
        let cfg = ProjectConfig::load(&dir.path().join(".sfkeyaudit.yaml"))
            .unwrap()
            .unwrap();
        let policy = cfg.policy.unwrap();
        assert_eq!(policy.pack, PolicyPackName::StrictCi);
        assert!(policy.require_owner);
    }

    #[test]
    fn policy_config_confidence_min_from_yaml() {
        use crate::patterns::ConfidenceTier;
        let dir = tmpdir();
        let yaml = "policy:\n  pack: strict_ci\n  confidence_min: high\n";
        fs::write(dir.path().join(".sfkeyaudit.yaml"), yaml).unwrap();
        let cfg = ProjectConfig::load(&dir.path().join(".sfkeyaudit.yaml"))
            .unwrap()
            .unwrap();
        let policy = cfg.policy.unwrap();
        assert_eq!(policy.confidence_min, Some(ConfidenceTier::High));
    }

    #[test]
    fn policy_config_confidence_min_absent_when_not_set() {
        let dir = tmpdir();
        let yaml = "policy:\n  pack: strict_ci\n";
        fs::write(dir.path().join(".sfkeyaudit.yaml"), yaml).unwrap();
        let cfg = ProjectConfig::load(&dir.path().join(".sfkeyaudit.yaml"))
            .unwrap()
            .unwrap();
        let policy = cfg.policy.unwrap();
        assert_eq!(policy.confidence_min, None);
    }

    #[test]
    fn load_plugin_rules_from_dir() {
        let dir = tmpdir();
        let plugin_dir = dir.path().join("plugins");
        fs::create_dir(&plugin_dir).unwrap();
        let yaml = r#"
- id: custom-secret-v1
  provider: my-svc
  pattern: "(?P<body>mysvc_[A-Za-z0-9]{20})"
  severity: high
- id: custom-token-v1
  provider: my-svc
  pattern: "(?P<body>myt_[A-Za-z0-9]{32})"
"#;
        fs::write(plugin_dir.join("my-rules.yaml"), yaml).unwrap();
        // Also write a non-YAML file that should be ignored.
        fs::write(plugin_dir.join("readme.txt"), "not a yaml file").unwrap();

        let rules = load_plugin_rules(&[plugin_dir]).unwrap();
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].id, "custom-secret-v1");
        assert_eq!(rules[1].id, "custom-token-v1");
    }

    #[test]
    fn load_plugin_rules_skips_missing_dir() {
        let dir = tmpdir();
        let missing = dir.path().join("no-such-dir");
        let rules = load_plugin_rules(&[missing]).unwrap();
        assert!(rules.is_empty());
    }

    #[test]
    fn load_plugin_rules_skips_malformed_file() {
        let dir = tmpdir();
        let plugin_dir = dir.path().join("plugins");
        fs::create_dir(&plugin_dir).unwrap();
        fs::write(plugin_dir.join("bad.yaml"), "this is not valid: {yaml: [").unwrap();
        // Should not error — just skips the bad file.
        let rules = load_plugin_rules(&[plugin_dir]).unwrap();
        assert!(rules.is_empty());
    }

    #[test]
    fn config_parses_plugin_dirs_and_custom_validators() {
        let dir = tmpdir();
        let yaml = r#"
plugin_dirs:
  - ./plugins
custom_validators:
  - provider: my-internal
    url: "https://api.internal.example.com/v1/check"
    auth_method: bearer
"#;
        fs::write(dir.path().join(".sfkeyaudit.yaml"), yaml).unwrap();
        let cfg = ProjectConfig::load(&dir.path().join(".sfkeyaudit.yaml"))
            .unwrap()
            .unwrap();
        assert_eq!(cfg.plugin_dirs.len(), 1);
        assert_eq!(cfg.custom_validators.len(), 1);
        assert_eq!(cfg.custom_validators[0].provider, "my-internal");
    }
}
