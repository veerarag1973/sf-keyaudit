//! Baseline support — generate a snapshot of accepted findings and compare
//! future scans against it so only newly introduced secrets fail the build.
//!
//! A baseline file is a JSON document whose `fingerprints` map contains one
//! entry per accepted finding.  Each entry records when the fingerprint was
//! first/last seen, which provider/pattern it belongs to, and optional
//! approval metadata.
//!
//! When `--baseline <FILE>` is supplied, any finding whose fingerprint appears
//! in the map is moved to `baselined_findings` and excluded from the
//! exit-code calculation.
//!
//! # Backward compatibility
//! Pre-v2.1 baseline files stored `fingerprints` as a JSON array of strings.
//! The loader auto-migrates that format to the new map format on first load.

use crate::error::AuditError;
use crate::types::Finding;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

// ── Structs ───────────────────────────────────────────────────────────────────

/// Per-fingerprint metadata stored in the baseline file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineEntry {
    pub fingerprint: String,
    pub first_seen: String,
    pub last_seen: String,
    #[serde(default)]
    pub provider: String,
    #[serde(default)]
    pub file: String,
    #[serde(default)]
    pub pattern_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approved_by: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approved_at: Option<String>,
}

impl BaselineEntry {
    fn new_from_finding(f: &Finding, now: &str) -> Self {
        Self {
            fingerprint: f.fingerprint.clone(),
            first_seen: now.to_string(),
            last_seen: now.to_string(),
            provider: f.provider.clone(),
            file: f.file.clone(),
            pattern_id: f.pattern_id.clone(),
            approved_by: None,
            approved_at: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Baseline {
    pub created_at: String,
    #[serde(default)]
    pub updated_at: String,
    pub tool_version: String,
    pub fingerprints: HashMap<String, BaselineEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approved_by: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approved_at: Option<String>,
}

impl Baseline {
    pub fn generate(findings: &[Finding], tool_version: &str) -> Self {
        let now = Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
        let mut fingerprints = HashMap::new();
        for f in findings {
            fingerprints
                .entry(f.fingerprint.clone())
                .or_insert_with(|| BaselineEntry::new_from_finding(f, &now));
        }
        Self {
            created_at: now.clone(),
            updated_at: now,
            tool_version: tool_version.to_string(),
            fingerprints,
            approved_by: None,
            approved_at: None,
        }
    }

    pub fn save(&self, path: &Path) -> Result<(), AuditError> {
        let json = serde_json::to_string_pretty(self).map_err(AuditError::Serialization)?;
        std::fs::write(path, json).map_err(|e| {
            AuditError::Config(format!("cannot write baseline to {}: {e}", path.display()))
        })
    }

    pub fn load(path: &Path) -> Result<Self, AuditError> {
        let content = std::fs::read_to_string(path).map_err(|e| {
            AuditError::Config(format!("cannot read baseline {}: {e}", path.display()))
        })?;
        if let Ok(bl) = serde_json::from_str::<Baseline>(&content) {
            return Ok(bl);
        }
        Self::migrate_legacy(&content).ok_or_else(|| {
            AuditError::Config(format!("malformed baseline file {}", path.display()))
        })
    }

    fn migrate_legacy(content: &str) -> Option<Self> {
        #[derive(Deserialize)]
        struct LegacyBaseline {
            created_at: String,
            #[serde(default)]
            tool_version: String,
            fingerprints: Vec<String>,
        }
        let raw: LegacyBaseline = serde_json::from_str(content).ok()?;
        let now = Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
        let fingerprints: HashMap<String, BaselineEntry> = raw
            .fingerprints
            .into_iter()
            .map(|fp| {
                let entry = BaselineEntry {
                    fingerprint: fp.clone(),
                    first_seen: raw.created_at.clone(),
                    last_seen: now.clone(),
                    provider: String::new(),
                    file: String::new(),
                    pattern_id: String::new(),
                    approved_by: None,
                    approved_at: None,
                };
                (fp, entry)
            })
            .collect();
        Some(Baseline {
            created_at: raw.created_at,
            updated_at: now,
            tool_version: raw.tool_version,
            fingerprints,
            approved_by: None,
            approved_at: None,
        })
    }

    pub fn contains(&self, finding: &Finding) -> bool {
        self.fingerprints.contains_key(&finding.fingerprint)
    }

    pub fn len(&self) -> usize {
        self.fingerprints.len()
    }

    pub fn is_empty(&self) -> bool {
        self.fingerprints.is_empty()
    }

    pub fn apply_enriched(&self, findings: &[Finding]) -> (Vec<Finding>, Vec<Finding>) {
        let mut new_findings: Vec<Finding> = Vec::new();
        let mut baselined: Vec<Finding> = Vec::new();
        for f in findings {
            if self.contains(f) {
                if let Some(entry) = self.fingerprints.get(&f.fingerprint) {
                    let mut suppressed = f.clone();
                    suppressed.first_seen = Some(entry.first_seen.clone());
                    suppressed.last_seen = Some(entry.last_seen.clone());
                    suppressed.suppression_provenance =
                        Some(format!("baseline:{}", entry.fingerprint));
                    baselined.push(suppressed);
                }
            } else {
                new_findings.push(f.clone());
            }
        }
        (new_findings, baselined)
    }

    pub fn refresh_timestamps(&mut self, current_findings: &[Finding]) {
        let now = Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
        for f in current_findings {
            if let Some(entry) = self.fingerprints.get_mut(&f.fingerprint) {
                entry.last_seen = now.clone();
            }
        }
        self.updated_at = now;
    }

    pub fn prune(&mut self, current_findings: &[Finding]) -> Vec<String> {
        let live: std::collections::HashSet<&str> =
            current_findings.iter().map(|f| f.fingerprint.as_str()).collect();
        let stale: Vec<String> = self
            .fingerprints
            .keys()
            .filter(|fp| !live.contains(fp.as_str()))
            .cloned()
            .collect();
        for fp in &stale {
            self.fingerprints.remove(fp);
        }
        if !stale.is_empty() {
            self.updated_at = Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
        }
        stale
    }

    pub fn merge(&mut self, findings: &[Finding]) -> usize {
        let now = Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
        let mut added = 0usize;
        for f in findings {
            if let Some(entry) = self.fingerprints.get_mut(&f.fingerprint) {
                entry.last_seen = now.clone();
            } else {
                self.fingerprints.insert(
                    f.fingerprint.clone(),
                    BaselineEntry::new_from_finding(f, &now),
                );
                added += 1;
            }
        }
        if added > 0 {
            self.updated_at = now;
        }
        added
    }
}

#[cfg(test)]
#[allow(clippy::cloned_ref_to_slice_refs)]
mod tests {
    use super::*;
    use crate::types::Finding;
    use tempfile::TempDir;

    fn tmpdir() -> TempDir { tempfile::tempdir().unwrap() }

    fn make_finding(pattern_id: &str, file: &str, line: usize) -> Finding {
        // Include `line` in match_text so each call produces a unique match body
        // and therefore a unique content-based fingerprint, just as the real
        // scanner would for two distinct secrets at different positions.
        Finding::new(1, "openai", file, line, 1, format!("sk-body{line}***REDACTED***"), pattern_id, 4.5)
    }

    #[test]
    fn generate_stores_fingerprint_entries() {
        let f1 = make_finding("openai-legacy-key-v1", "src/a.py", 1);
        let f2 = make_finding("anthropic-api-key-v1", "src/b.py", 2);
        let bl = Baseline::generate(&[f1.clone(), f2.clone()], "2.1.0");
        assert_eq!(bl.fingerprints.len(), 2);
        assert!(bl.fingerprints.contains_key(&f1.fingerprint));
        assert!(bl.fingerprints.contains_key(&f2.fingerprint));
    }

    #[test]
    fn generate_populates_entry_metadata() {
        let f = make_finding("openai-legacy-key-v1", "src/a.py", 1);
        let bl = Baseline::generate(&[f.clone()], "2.1.0");
        let entry = bl.fingerprints.get(&f.fingerprint).unwrap();
        assert_eq!(entry.provider, "openai");
        assert_eq!(entry.file, "src/a.py");
        assert_eq!(entry.pattern_id, "openai-legacy-key-v1");
        assert!(!entry.first_seen.is_empty());
    }

    #[test]
    fn contains_returns_true_for_known_fingerprint() {
        let f = make_finding("openai-legacy-key-v1", "src/a.py", 1);
        let bl = Baseline::generate(&[f.clone()], "2.1.0");
        assert!(bl.contains(&f));
    }

    #[test]
    fn contains_returns_false_for_unknown_fingerprint() {
        let f1 = make_finding("openai-legacy-key-v1", "src/a.py", 1);
        let f2 = make_finding("openai-legacy-key-v1", "src/a.py", 2);
        let bl = Baseline::generate(&[f1], "2.1.0");
        assert!(!bl.contains(&f2));
    }

    #[test]
    fn apply_partitions_correctly() {
        let f1 = make_finding("openai-legacy-key-v1", "src/a.py", 1);
        let f2 = make_finding("anthropic-api-key-v1", "src/b.py", 2);
        let f3 = make_finding("groq-api-key-v1", "src/c.py", 3);
        let bl = Baseline::generate(&[f1.clone()], "2.1.0");
        let all = vec![f1, f2.clone(), f3.clone()];
        let (new, baselined) = bl.apply_enriched(&all);
        assert_eq!(new.len(), 2);
        assert_eq!(baselined.len(), 1);
    }

    #[test]
    fn apply_enriched_populates_suppression_provenance() {
        let f = make_finding("openai-legacy-key-v1", "src/a.py", 1);
        let bl = Baseline::generate(&[f.clone()], "2.1.0");
        let (new, baselined) = bl.apply_enriched(&[f.clone()]);
        assert!(new.is_empty());
        assert_eq!(baselined.len(), 1);
        let prov = baselined[0].suppression_provenance.as_deref().unwrap_or("");
        assert!(prov.starts_with("baseline:fp-"));
        assert!(baselined[0].first_seen.is_some());
    }

    #[test]
    fn save_and_load_roundtrip() {
        let dir = tmpdir();
        let path = dir.path().join("baseline.json");
        let f = make_finding("openai-legacy-key-v1", "src/a.py", 5);
        let bl = Baseline::generate(&[f.clone()], "2.1.0");
        bl.save(&path).unwrap();
        let loaded = Baseline::load(&path).unwrap();
        assert!(loaded.contains(&f));
        assert_eq!(loaded.tool_version, "2.1.0");
    }

    #[test]
    fn prune_removes_stale_entries() {
        let f1 = make_finding("openai-legacy-key-v1", "src/a.py", 1);
        let f2 = make_finding("anthropic-api-key-v1", "src/b.py", 2);
        let mut bl = Baseline::generate(&[f1.clone(), f2.clone()], "2.1.0");
        let pruned = bl.prune(&[f1.clone()]);
        assert_eq!(pruned.len(), 1);
        assert!(pruned.contains(&f2.fingerprint));
        assert_eq!(bl.fingerprints.len(), 1);
    }

    #[test]
    fn prune_empty_when_nothing_to_remove() {
        let f = make_finding("openai-legacy-key-v1", "src/a.py", 1);
        let mut bl = Baseline::generate(&[f.clone()], "2.1.0");
        let pruned = bl.prune(&[f.clone()]);
        assert!(pruned.is_empty());
    }

    #[test]
    fn merge_adds_new_entries() {
        let f1 = make_finding("openai-legacy-key-v1", "src/a.py", 1);
        let f2 = make_finding("anthropic-api-key-v1", "src/b.py", 2);
        let mut bl = Baseline::generate(&[f1.clone()], "2.1.0");
        let added = bl.merge(&[f1.clone(), f2.clone()]);
        assert_eq!(added, 1);
        assert_eq!(bl.fingerprints.len(), 2);
    }

    #[test]
    fn load_migrates_legacy_array_format() {
        let dir = tmpdir();
        let path = dir.path().join("old.json");
        std::fs::write(
            &path,
            r#"{"created_at":"2024-01-01T00:00:00Z","tool_version":"2.0.0","fingerprints":["fp-aabbcc112233","fp-ddeeff445566"]}"#,
        ).unwrap();
        let bl = Baseline::load(&path).unwrap();
        assert_eq!(bl.fingerprints.len(), 2);
        assert!(bl.fingerprints.contains_key("fp-aabbcc112233"));
    }
}
