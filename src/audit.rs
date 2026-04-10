//! Append-only JSONL audit log.
//!
//! Every security-relevant operation emits an [`AuditEvent`] that is
//! serialised as a single JSON line and appended to a log file.  The file can
//! be shipped to a SIEM, signed, or stored in an immutable S3 bucket.
//!
//! # Format
//! Each line is a self-contained JSON object:
//! ```json
//! {"timestamp":"2024-01-15T12:34:56.789Z","actor":"ci-bot","repository":"acme/backend",
//!  "scan_id":"b9e8a5c2-…","event_type":"scan_completed","payload":{…}}
//! ```
//!
//! # Guarantees
//! * Writes are flushed immediately after each event (`sync_all` after write).
//! * If the log path cannot be opened, [`AuditLog::append`] returns an `Err`
//!   rather than silently dropping the event.
//! * Fingerprint of each finding is included where applicable to allow
//!   correlating events with findings in the report.

use crate::error::AuditError;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

// ── Event types ────────────────────────────────────────────────────────────────

/// Every distinct event that can be written to the audit log.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[allow(clippy::large_enum_variant)]
pub enum AuditEventKind {
    /// A scan run has started.
    ScanStarted {
        scan_root: String,
        provider_filter: Vec<String>,
    },
    /// A scan run has finished.
    ScanCompleted {
        scan_id: String,
        total_findings: usize,
        high_confidence: usize,
        policy_blocks: usize,
        duration_ms: u64,
    },
    /// A finding's triage state was changed by an operator.
    TriageStateChanged {
        fingerprint: String,
        old_state: String,
        new_state: String,
        justification: Option<String>,
    },
    /// A suppression or allowlist entry was created.
    SuppressionCreated {
        fingerprint: String,
        reason: String,
        expires_at: Option<String>,
    },
    /// A baseline snapshot was generated or updated.
    BaselineGenerated {
        path: String,
        entry_count: usize,
    },
    /// Network validation was executed for a finding.
    ValidationExecuted {
        fingerprint: String,
        provider: String,
        status: String,
    },
    /// A policy pack was evaluated and a blocking violation was found.
    PolicyViolation {
        fingerprint: String,
        rule: String,
        decision: String,
        justification: String,
    },
}

/// A single entry in the append-only audit log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// RFC 3339 / ISO-8601 UTC timestamp of the event.
    pub timestamp: String,
    /// Identity that triggered the event (e.g. `"ci-bot"`, git email, username).
    pub actor: String,
    /// Repository identifier (e.g. `"org/repo"`).  May be empty.
    pub repository: String,
    /// Stable scan-run UUID for correlating all events from one invocation.
    pub scan_id: String,
    /// The event payload.
    pub event: AuditEventKind,
}

// ── Log writer ─────────────────────────────────────────────────────────────────

/// Append-only JSONL audit log handle.
///
/// Create with [`AuditLog::open`] or [`AuditLog::disabled`].
pub struct AuditLog {
    path: Option<PathBuf>,
    actor: String,
    repository: String,
    scan_id: String,
}

impl AuditLog {
    /// Open (or create) the audit log at `path`.
    ///
    /// # Errors
    /// Returns [`AuditError::Io`] if the file cannot be opened/created.
    pub fn open(
        path: &Path,
        actor: impl Into<String>,
        repository: impl Into<String>,
        scan_id: impl Into<String>,
    ) -> Result<Self, AuditError> {
        // Pre-flight: try opening the file to fail early with a clear error.
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|e| {
                AuditError::AuditLog(format!(
                    "cannot open audit log '{}': {e}",
                    path.display()
                ))
            })?;
        Ok(Self {
            path: Some(path.to_path_buf()),
            actor: actor.into(),
            repository: repository.into(),
            scan_id: scan_id.into(),
        })
    }

    /// Return a no-op audit log that discards all events.
    pub fn disabled() -> Self {
        Self {
            path: None,
            actor: String::new(),
            repository: String::new(),
            scan_id: String::new(),
        }
    }

    /// Return `true` if this log is active (not disabled).
    pub fn is_active(&self) -> bool {
        self.path.is_some()
    }

    /// Append a single event to the log.
    ///
    /// The write is `fsync`'d after every call to ensure durability.
    ///
    /// # Errors
    /// Returns [`AuditError::Io`] on I/O failure.  The caller should treat
    /// this as non-fatal in most contexts (log the error, continue the scan).
    pub fn append(&self, event: AuditEventKind) -> Result<(), AuditError> {
        let path = match &self.path {
            Some(p) => p,
            None => return Ok(()), // disabled
        };

        let entry = AuditEntry {
            timestamp: Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            actor: self.actor.clone(),
            repository: self.repository.clone(),
            scan_id: self.scan_id.clone(),
            event,
        };

        let mut line = serde_json::to_string(&entry).map_err(|e| {
            AuditError::AuditLog(format!("audit serialisation failed: {e}"))
        })?;
        line.push('\n');

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|e| {
                AuditError::AuditLog(format!(
                    "cannot open audit log '{}': {e}",
                    path.display()
                ))
            })?;

        file.write_all(line.as_bytes()).map_err(|e| {
            AuditError::AuditLog(format!("audit write failed: {e}"))
        })?;

        file.sync_all().map_err(|e| {
            AuditError::AuditLog(format!("audit fsync failed: {e}"))
        })?;

        Ok(())
    }

    /// Convenience wrapper: append and log a warning on failure (never panics).
    pub fn record(&self, event: AuditEventKind) {
        if !self.is_active() {
            return;
        }
        if let Err(e) = self.append(event) {
            tracing::warn!(error = %e, "failed to write audit log entry");
        }
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn tmpdir() -> TempDir {
        tempfile::tempdir().unwrap()
    }

    #[test]
    fn disabled_log_does_nothing() {
        let log = AuditLog::disabled();
        assert!(!log.is_active());
        // Should succeed without creating any file.
        log.record(AuditEventKind::ScanStarted {
            scan_root: "/".into(),
            provider_filter: vec![],
        });
    }

    #[test]
    fn enabled_log_creates_file_and_appends_jsonl() {
        let dir = tmpdir();
        let path = dir.path().join("audit.jsonl");
        let log =
            AuditLog::open(&path, "test-actor", "org/repo", "scan-id-001").unwrap();
        assert!(log.is_active());

        log.record(AuditEventKind::ScanStarted {
            scan_root: "/src".into(),
            provider_filter: vec!["openai".into()],
        });
        log.record(AuditEventKind::ScanCompleted {
            scan_id: "scan-id-001".into(),
            total_findings: 3,
            high_confidence: 2,
            policy_blocks: 1,
            duration_ms: 420,
        });

        let content = fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 2);

        // Each line must be valid JSON with required fields.
        for line in &lines {
            let v: serde_json::Value = serde_json::from_str(line).unwrap();
            assert!(v["timestamp"].is_string());
            assert_eq!(v["actor"], "test-actor");
            assert_eq!(v["repository"], "org/repo");
        }
    }

    #[test]
    fn triage_state_changed_roundtrips() {
        let dir = tmpdir();
        let path = dir.path().join("audit.jsonl");
        let log = AuditLog::open(&path, "alice", "acme/backend", "s-001").unwrap();
        log.record(AuditEventKind::TriageStateChanged {
            fingerprint: "fp-deadbeef".into(),
            old_state: "open".into(),
            new_state: "false_positive".into(),
            justification: Some("test fixture".into()),
        });
        let raw = fs::read_to_string(&path).unwrap();
        let entry: AuditEntry = serde_json::from_str(raw.trim()).unwrap();
        match entry.event {
            AuditEventKind::TriageStateChanged { new_state, .. } => {
                assert_eq!(new_state, "false_positive");
            }
            _ => panic!("wrong event type"),
        }
    }

    // ── AuditEventKind serialisation ───────────────────────────────────────────

    #[test]
    fn scan_started_event_serializes() {
        let dir = tmpdir();
        let path = dir.path().join("audit.jsonl");
        let log = AuditLog::open(&path, "ci", "org/repo", "s-001").unwrap();
        log.record(AuditEventKind::ScanStarted {
            scan_root: "/workspace".into(),
            provider_filter: vec!["openai".into(), "anthropic".into()],
        });
        let raw = fs::read_to_string(&path).unwrap();
        let entry: AuditEntry = serde_json::from_str(raw.trim()).unwrap();
        match entry.event {
            AuditEventKind::ScanStarted { scan_root, provider_filter } => {
                assert_eq!(scan_root, "/workspace");
                assert_eq!(provider_filter, vec!["openai", "anthropic"]);
            }
            _ => panic!("wrong event type"),
        }
    }

    #[test]
    fn scan_completed_event_serializes() {
        let dir = tmpdir();
        let path = dir.path().join("audit.jsonl");
        let log = AuditLog::open(&path, "ci", "org/repo", "s-002").unwrap();
        log.record(AuditEventKind::ScanCompleted {
            scan_id: "s-002".into(),
            total_findings: 5,
            high_confidence: 3,
            policy_blocks: 2,
            duration_ms: 1234,
        });
        let raw = fs::read_to_string(&path).unwrap();
        let entry: AuditEntry = serde_json::from_str(raw.trim()).unwrap();
        match entry.event {
            AuditEventKind::ScanCompleted { total_findings, duration_ms, .. } => {
                assert_eq!(total_findings, 5);
                assert_eq!(duration_ms, 1234);
            }
            _ => panic!("wrong event type"),
        }
    }

    #[test]
    fn policy_violation_event_serializes() {
        let dir = tmpdir();
        let path = dir.path().join("audit.jsonl");
        let log = AuditLog::open(&path, "ci", "org/repo", "s-003").unwrap();
        log.record(AuditEventKind::PolicyViolation {
            fingerprint: "fp-abc123".into(),
            rule: "severity:strict-ci:high".into(),
            decision: "block".into(),
            justification: "high finding exceeds threshold".into(),
        });
        let raw = fs::read_to_string(&path).unwrap();
        let entry: AuditEntry = serde_json::from_str(raw.trim()).unwrap();
        match entry.event {
            AuditEventKind::PolicyViolation { fingerprint, decision, .. } => {
                assert_eq!(fingerprint, "fp-abc123");
                assert_eq!(decision, "block");
            }
            _ => panic!("wrong event type"),
        }
    }

    #[test]
    fn validation_executed_event_serializes() {
        let dir = tmpdir();
        let path = dir.path().join("audit.jsonl");
        let log = AuditLog::open(&path, "ci", "org/repo", "s-004").unwrap();
        log.record(AuditEventKind::ValidationExecuted {
            fingerprint: "fp-xyz789".into(),
            provider: "openai".into(),
            status: "likely-valid".into(),
        });
        let raw = fs::read_to_string(&path).unwrap();
        let entry: AuditEntry = serde_json::from_str(raw.trim()).unwrap();
        match entry.event {
            AuditEventKind::ValidationExecuted { provider, status, .. } => {
                assert_eq!(provider, "openai");
                assert_eq!(status, "likely-valid");
            }
            _ => panic!("wrong event type"),
        }
    }

    #[test]
    fn audit_entry_includes_actor_repo_scan_id() {
        let dir = tmpdir();
        let path = dir.path().join("audit.jsonl");
        let log = AuditLog::open(&path, "security-bot", "acme/monorepo", "scan-xyz").unwrap();
        log.record(AuditEventKind::ScanStarted {
            scan_root: "/".into(),
            provider_filter: vec![],
        });
        let raw = fs::read_to_string(&path).unwrap();
        let v: serde_json::Value = serde_json::from_str(raw.trim()).unwrap();
        assert_eq!(v["actor"], "security-bot");
        assert_eq!(v["repository"], "acme/monorepo");
        assert_eq!(v["scan_id"], "scan-xyz");
        assert!(v["timestamp"].is_string());
    }
}
