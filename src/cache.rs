//! Hash-based incremental scan cache.
//!
//! The cache stores the SHA-256 hash of each scanned file's content.  On
//! subsequent runs, files whose hash hasn't changed are skipped.  This avoids
//! re-scanning unchanged files in large repositories, improving throughput
//! without affecting correctness: the report is always based on the current
//! file contents for any file that has changed.
//!
//! The cache file is JSON (default name: `.sfkeyaudit-cache.json`) and is
//! human-readable / VCS-diffable.  It is safe to delete — the tool simply
//! re-builds it on the next run.
//!
//! # Limitations
//! The cache does NOT store previous findings.  It is purely a "skip re-scan
//! of unchanged files" optimisation.  The report reflects the current state of
//! all changed or newly encountered files.

use crate::error::AuditError;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::Path;

/// One entry per file in the cache.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheEntry {
    /// Lowercase hex SHA-256 of the file content at last scan.
    pub hash: String,
    /// ISO-8601 UTC timestamp of the last scan.
    pub last_scanned: String,
    /// Number of high-confidence findings from the last scan of this file.
    pub findings_count: usize,
}

/// In-memory scan cache backed by a JSON file.
#[derive(Debug, Default)]
pub struct ScanCache {
    entries: HashMap<String, CacheEntry>,
    /// `true` when entries have been modified and the cache needs saving.
    dirty: bool,
}

impl ScanCache {
    /// Load from `path`.  Returns an empty cache (no error) when the file does
    /// not exist or cannot be parsed.
    pub fn load(path: &Path) -> Self {
        if !path.exists() {
            return Self::default();
        }
        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => return Self::default(),
        };
        let entries: HashMap<String, CacheEntry> = match serde_json::from_str(&content) {
            Ok(e) => e,
            Err(_) => return Self::default(),
        };
        Self { entries, dirty: false }
    }

    /// Save the cache to `path` if it has been modified since last load.
    /// Does nothing when the cache is clean.
    pub fn save(&self, path: &Path) -> Result<(), AuditError> {
        if !self.dirty {
            return Ok(());
        }
        let json = serde_json::to_string_pretty(&self.entries)
            .map_err(AuditError::Serialization)?;
        std::fs::write(path, json).map_err(|e| {
            AuditError::Config(format!(
                "cannot write cache file {}: {e}",
                path.display()
            ))
        })
    }

    /// Check whether `file_path` exists in the cache with the given `content_hash`.
    ///
    /// Returns `Some(&CacheEntry)` when the file was last scanned with the
    /// identical content hash, indicating it can be safely skipped.
    /// Returns `None` when the file is new or its content has changed.
    pub fn check(&self, file_path: &str, content_hash: &str) -> Option<&CacheEntry> {
        self.entries
            .get(file_path)
            .filter(|e| e.hash == content_hash)
    }

    /// Record that `file_path` was scanned and produced `findings_count`
    /// high-confidence findings.  Marks the cache as dirty.
    pub fn update(&mut self, file_path: String, content_hash: String, findings_count: usize) {
        self.entries.insert(
            file_path,
            CacheEntry {
                hash: content_hash,
                last_scanned: Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
                findings_count,
            },
        );
        self.dirty = true;
    }

    /// Number of entries currently in the cache.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Compute a lowercase hex SHA-256 hash of `data`.
pub fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn tmpdir() -> TempDir {
        tempfile::tempdir().unwrap()
    }

    #[test]
    fn sha256_hex_is_deterministic() {
        let h1 = sha256_hex(b"hello world");
        let h2 = sha256_hex(b"hello world");
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64, "SHA-256 hex must be 64 chars");
    }

    #[test]
    fn sha256_different_inputs_produce_different_hashes() {
        assert_ne!(sha256_hex(b"hello"), sha256_hex(b"world"));
    }

    #[test]
    fn empty_cache_check_returns_none() {
        let cache = ScanCache::default();
        assert!(cache.check("src/main.rs", "deadbeef").is_none());
    }

    #[test]
    fn update_then_same_hash_returns_entry() {
        let mut cache = ScanCache::default();
        cache.update("src/main.rs".into(), "hashvalue".into(), 0);
        assert!(cache.check("src/main.rs", "hashvalue").is_some());
    }

    #[test]
    fn check_returns_none_when_hash_differs() {
        let mut cache = ScanCache::default();
        cache.update("src/main.rs".into(), "old_hash".into(), 0);
        assert!(cache.check("src/main.rs", "new_hash").is_none());
    }

    #[test]
    fn findings_count_stored_correctly() {
        let mut cache = ScanCache::default();
        cache.update("secret.py".into(), "abc".into(), 3);
        let entry = cache.check("secret.py", "abc").unwrap();
        assert_eq!(entry.findings_count, 3);
    }

    #[test]
    fn save_and_load_roundtrip() {
        let dir = tmpdir();
        let path = dir.path().join("cache.json");

        let mut cache = ScanCache::default();
        cache.update("file.py".into(), "hash123".into(), 2);
        cache.save(&path).unwrap();

        let loaded = ScanCache::load(&path);
        assert!(!loaded.is_empty());
        let e = loaded.check("file.py", "hash123").unwrap();
        assert_eq!(e.findings_count, 2);
    }

    #[test]
    fn load_nonexistent_file_returns_empty_cache() {
        let cache = ScanCache::load(Path::new("/no/such/cache.json"));
        assert!(cache.is_empty());
    }

    #[test]
    fn save_clean_cache_does_not_write_file() {
        let dir = tmpdir();
        let path = dir.path().join("cache.json");
        // Load a non-existent file → empty, not dirty → save is a no-op.
        let cache = ScanCache::load(&path);
        cache.save(&path).unwrap();
        assert!(!path.exists(), "clean cache must not write a file");
    }

    #[test]
    fn len_reflects_entry_count() {
        let mut cache = ScanCache::default();
        assert_eq!(cache.len(), 0);
        cache.update("a.py".into(), "x".into(), 0);
        cache.update("b.py".into(), "y".into(), 0);
        assert_eq!(cache.len(), 2);
    }
}
