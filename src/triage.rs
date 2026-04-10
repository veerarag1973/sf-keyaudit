//! Triage state store — persists finding lifecycle decisions across scans.
//!
//! A triage store is a simple JSON file (`.sfkeyaudit-triage.json` by default)
//! that maps finding fingerprints to their current [`TriageEntry`].  The file
//! is updated by the `sf-keyaudit triage set` subcommand and read at scan time
//! (via `--triage-store`) so that suppressed or acknowledged findings are
//! annotated in every subsequent report.
//!
//! # Format
//! ```json
//! {
//!   "fingerprints": {
//!     "fp-a1b2c3d4e5f6g7h8": {
//!       "state": "false_positive",
//!       "justification": "This is a test fixture value, not a real credential.",
//!       "actor": "alice",
//!       "updated_at": "2026-04-10T12:00:00Z"
//!     }
//!   }
//! }
//! ```

use crate::error::AuditError;
use crate::types::{Finding, TriageState};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

/// A single triage decision for one finding fingerprint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriageEntry {
    /// The new triage lifecycle state.
    pub state: TriageState,
    /// Optional free-text justification.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub justification: Option<String>,
    /// Identity that recorded this decision.
    pub actor: String,
    /// ISO-8601 UTC timestamp of when the decision was recorded.
    pub updated_at: String,
}

/// In-memory representation of the triage state store.
///
/// Build with [`TriageStore::load`] or [`TriageStore::load_or_create`];
/// persist with [`TriageStore::save`].
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TriageStore {
    /// Map from fingerprint string to its current triage entry.
    #[serde(default)]
    pub fingerprints: HashMap<String, TriageEntry>,
}

impl TriageStore {
    /// Load a store from `path`.
    ///
    /// Returns `Err` if the file exists but cannot be read or parsed.
    /// Returns `Ok(empty store)` if the file does not exist.
    pub fn load_or_create(path: &Path) -> Result<Self, AuditError> {
        if !path.exists() {
            return Ok(Self::default());
        }
        Self::load(path)
    }

    /// Load a store from `path`.  The file must exist and be valid JSON.
    pub fn load(path: &Path) -> Result<Self, AuditError> {
        let content = std::fs::read_to_string(path).map_err(|e| {
            AuditError::Config(format!(
                "cannot read triage store '{}': {e}",
                path.display()
            ))
        })?;
        serde_json::from_str(&content).map_err(|e| {
            AuditError::Config(format!(
                "malformed triage store '{}': {e}",
                path.display()
            ))
        })
    }

    /// Persist the store to `path` as pretty-printed JSON.
    pub fn save(&self, path: &Path) -> Result<(), AuditError> {
        let json = serde_json::to_string_pretty(self).map_err(|e| {
            AuditError::Config(format!("triage store serialisation failed: {e}"))
        })?;
        std::fs::write(path, json).map_err(|e| {
            AuditError::Config(format!(
                "cannot write triage store '{}': {e}",
                path.display()
            ))
        })
    }

    /// Insert or overwrite the triage entry for `fingerprint`.
    ///
    /// Returns the old entry if one existed.
    pub fn set(&mut self, fingerprint: String, entry: TriageEntry) -> Option<TriageEntry> {
        self.fingerprints.insert(fingerprint, entry)
    }

    /// Look up the entry for `fingerprint`.
    pub fn get(&self, fingerprint: &str) -> Option<&TriageEntry> {
        self.fingerprints.get(fingerprint)
    }

    /// Apply stored triage states to a mutable slice of findings.
    ///
    /// For each finding whose fingerprint has an entry in the store, the
    /// `triage_state` and `triage_justification` fields are updated in place.
    pub fn apply(&self, findings: &mut Vec<Finding>) {
        for f in findings.iter_mut() {
            if let Some(entry) = self.fingerprints.get(&f.fingerprint) {
                f.triage_state = Some(entry.state);
                f.triage_justification = entry.justification.clone();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::TriageState;
    use tempfile::TempDir;

    fn tmpdir() -> TempDir {
        tempfile::tempdir().unwrap()
    }

    fn entry(state: TriageState, justification: Option<&str>) -> TriageEntry {
        TriageEntry {
            state,
            justification: justification.map(String::from),
            actor: "alice".into(),
            updated_at: "2026-04-10T00:00:00Z".into(),
        }
    }

    #[test]
    fn load_or_create_returns_empty_when_file_missing() {
        let dir = tmpdir();
        let path = dir.path().join("triage.json");
        let store = TriageStore::load_or_create(&path).unwrap();
        assert!(store.fingerprints.is_empty());
    }

    #[test]
    fn save_and_reload_roundtrip() {
        let dir = tmpdir();
        let path = dir.path().join("triage.json");
        let mut store = TriageStore::default();
        store.set(
            "fp-abc123".into(),
            entry(TriageState::FalsePositive, Some("test fixture")),
        );
        store.save(&path).unwrap();
        let loaded = TriageStore::load(&path).unwrap();
        let e = loaded.get("fp-abc123").unwrap();
        assert_eq!(e.state, TriageState::FalsePositive);
        assert_eq!(e.justification.as_deref(), Some("test fixture"));
    }

    #[test]
    fn set_returns_old_entry() {
        let mut store = TriageStore::default();
        let old = store.set("fp-001".into(), entry(TriageState::Open, None));
        assert!(old.is_none());
        let old2 = store.set("fp-001".into(), entry(TriageState::Fixed, None));
        assert!(old2.is_some());
        assert_eq!(old2.unwrap().state, TriageState::Open);
    }

    #[test]
    fn apply_updates_findings_in_place() {
        use crate::types::Finding;
        let mut store = TriageStore::default();
        store.set(
            // fingerprint will be computed from Finding::new below; we need
            // to match exactly so we build a Finding first and use its fp.
            "placeholder".into(),
            entry(TriageState::AcceptedRisk, Some("risk accepted")),
        );

        let f = Finding::new(
            1, "openai", "a.py", 1, 1,
            "sk-***REDACTED***".into(), "openai-legacy-key-v1", 4.5,
        );
        // Update the store key to the real fingerprint.
        let real_fp = f.fingerprint.clone();
        store.fingerprints.clear();
        store.set(real_fp.clone(), entry(TriageState::AcceptedRisk, Some("risk accepted")));

        let mut findings = vec![f];
        store.apply(&mut findings);
        assert_eq!(findings[0].triage_state, Some(TriageState::AcceptedRisk));
        assert_eq!(
            findings[0].triage_justification.as_deref(),
            Some("risk accepted")
        );
    }

    #[test]
    fn apply_leaves_unmatched_findings_unchanged() {
        use crate::types::Finding;
        let store = TriageStore::default(); // empty
        let f = Finding::new(
            1, "openai", "a.py", 1, 1,
            "sk-***REDACTED***".into(), "openai-legacy-key-v1", 4.5,
        );
        let mut findings = vec![f];
        store.apply(&mut findings);
        assert!(findings[0].triage_state.is_none());
    }

    #[test]
    fn get_returns_none_for_missing_fingerprint() {
        let store = TriageStore::default();
        assert!(store.get("fp-nonexistent").is_none());
    }
}
