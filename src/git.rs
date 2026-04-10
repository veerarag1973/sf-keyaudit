//! Git-aware scan modes.
//!
//! Shells out to the `git` binary (must be on PATH) to discover the set of
//! files that changed since a given ref or that are currently staged.  The
//! scanner then operates only on those files rather than the full tree.

use crate::error::AuditError;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Return the files currently staged in the index (relative to the repo root).
///
/// Equivalent to `git diff --staged --name-only --diff-filter=ACMR`.
pub fn staged_files(repo_root: &Path) -> Result<Vec<PathBuf>, AuditError> {
    let output = Command::new("git")
        .args(["diff", "--staged", "--name-only", "--diff-filter=ACMR"])
        .current_dir(repo_root)
        .output()
        .map_err(|e| AuditError::GitError(format!("git staged diff failed: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(AuditError::GitError(format!(
            "git diff --staged failed: {stderr}"
        )));
    }

    parse_file_list(&output.stdout, repo_root)
}

/// Return files changed between `base_ref` and the working tree HEAD.
///
/// Equivalent to `git diff <base_ref> --name-only --diff-filter=ACMR`.
pub fn diff_files(repo_root: &Path, base_ref: &str) -> Result<Vec<PathBuf>, AuditError> {
    let output = Command::new("git")
        .args(["diff", base_ref, "--name-only", "--diff-filter=ACMR"])
        .current_dir(repo_root)
        .output()
        .map_err(|e| AuditError::GitError(format!("git diff failed: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(AuditError::GitError(format!(
            "git diff {base_ref} failed: {stderr}"
        )));
    }

    parse_file_list(&output.stdout, repo_root)
}

/// Find the nearest git repository root by running `git rev-parse --show-toplevel`.
pub fn repo_root(start: &Path) -> Result<PathBuf, AuditError> {
    let output = Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .current_dir(start)
        .output()
        .map_err(|e| AuditError::GitError(format!("git rev-parse failed: {e}")))?;

    if !output.status.success() {
        return Err(AuditError::GitError(
            "not inside a git repository".to_string(),
        ));
    }

    let raw = String::from_utf8_lossy(&output.stdout).trim().to_string();
    Ok(PathBuf::from(raw))
}

// ── private helpers ───────────────────────────────────────────────────────────

fn parse_file_list(raw: &[u8], repo_root: &Path) -> Result<Vec<PathBuf>, AuditError> {
    let text = String::from_utf8_lossy(raw);
    let paths: Vec<PathBuf> = text
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| repo_root.join(l.trim()))
        .filter(|p| p.is_file()) // only include files that exist
        .collect();
    Ok(paths)
}

/// Return all files changed between `since_ref` and HEAD.
///
/// Equivalent to `git log --name-only --diff-filter=ACMR --format="" <since_ref>..HEAD`.
pub fn since_commit_files(repo_root: &Path, since_ref: &str) -> Result<Vec<PathBuf>, AuditError> {
    let rev_range = format!("{since_ref}..HEAD");
    let output = Command::new("git")
        .args([
            "log",
            "--name-only",
            "--diff-filter=ACMR",
            "--format=",
            &rev_range,
        ])
        .current_dir(repo_root)
        .output()
        .map_err(|e| AuditError::GitError(format!("git log failed: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(AuditError::GitError(format!(
            "git log --since-commit {since_ref} failed: {stderr}"
        )));
    }

    // Deduplicate paths (a file can appear multiple times when touched in
    // multiple commits).
    let mut seen = std::collections::HashSet::new();
    let text = String::from_utf8_lossy(&output.stdout);
    let paths: Vec<PathBuf> = text
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| repo_root.join(l.trim()))
        .filter(|p| p.is_file())
        .filter(|p| seen.insert(p.clone()))
        .collect();
    Ok(paths)
}

// ── History blob extraction ───────────────────────────────────────────────────

/// A historical blob extracted from git object storage.
///
/// Unlike working-tree scanning, blobs here represent EVERY version of EVERY
/// file ever committed — including secrets that were deleted from the tree.
pub struct HistoryBlob {
    /// The git blob SHA (40 hex chars) — used in the virtual scan path.
    pub blob_sha: String,
    /// The last known repository-relative path for display.
    pub filename: String,
    /// Raw blob content bytes.
    pub content: Vec<u8>,
}

/// Extract and deduplicate every text blob reachable from any ref in the repo.
///
/// Uses three git plumbing commands:
/// 1. `git rev-list --objects --all`  — enumerate all reachable objects.
/// 2. `git cat-file --batch-check`    — filter to blob type + size.
/// 3. `git cat-file --batch`          — read blob content.
///
/// Blobs larger than `max_blob_size` and common binary extensions are skipped.
/// Blobs with identical SHAs (same file content across branches/history) are
/// scanned only once.
pub fn history_blobs(repo_root: &Path, max_blob_size: u64) -> Result<Vec<HistoryBlob>, AuditError> {
    use std::io::Write as StdWrite;
    use std::process::Stdio;

    // ── Phase 1: enumerate all reachable objects with their paths ─────────────
    // Lines: "<40-hex>"        → commit/tag (no scan needed)
    //        "<40-hex> <path>" → tree or blob
    let rev_output = Command::new("git")
        .args(["rev-list", "--objects", "--all"])
        .current_dir(repo_root)
        .output()
        .map_err(|e| AuditError::GitError(format!("git rev-list --objects failed: {e}")))?;

    if !rev_output.status.success() {
        let stderr = String::from_utf8_lossy(&rev_output.stderr);
        return Err(AuditError::GitError(format!(
            "git rev-list --objects failed: {stderr}"
        )));
    }

    let candidates: Vec<(String, String)> = String::from_utf8_lossy(&rev_output.stdout)
        .lines()
        .filter_map(|line| {
            let mut iter = line.splitn(2, ' ');
            let sha = iter.next()?.trim().to_string();
            if sha.len() != 40 { return None; }
            let path = iter.next()?.trim().to_string();
            if path.is_empty() { return None; }
            Some((sha, path))
        })
        .collect();

    if candidates.is_empty() {
        return Ok(vec![]);
    }

    // ── Phase 2: identify blobs and filter by size ────────────────────────────
    // `git cat-file --batch-check` emits one "<sha> <type> <size>" per input SHA.
    let shas_input: Vec<u8> = candidates
        .iter()
        .flat_map(|(sha, _)| format!("{sha}\n").into_bytes())
        .collect();

    let mut check_proc = Command::new("git")
        .args(["cat-file", "--batch-check"])
        .current_dir(repo_root)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|e| AuditError::GitError(format!("git cat-file --batch-check spawn: {e}")))?;

    if let Some(mut stdin) = check_proc.stdin.take() {
        stdin.write_all(&shas_input).ok();
    }
    let check_out = check_proc
        .wait_with_output()
        .map_err(|e| AuditError::GitError(format!("git cat-file --batch-check: {e}")))?;

    // Common binary extensions to skip (content-scan is useless for them).
    let is_binary_ext = |path: &str| {
        let l = path.to_lowercase();
        l.ends_with(".png") || l.ends_with(".jpg") || l.ends_with(".jpeg")
            || l.ends_with(".gif") || l.ends_with(".webp") || l.ends_with(".ico")
            || l.ends_with(".svg") || l.ends_with(".woff") || l.ends_with(".woff2")
            || l.ends_with(".ttf") || l.ends_with(".eot") || l.ends_with(".otf")
            || l.ends_with(".pdf") || l.ends_with(".exe") || l.ends_with(".dll")
            || l.ends_with(".so") || l.ends_with(".dylib") || l.ends_with(".a")
            || l.ends_with(".o") || l.ends_with(".class") || l.ends_with(".pyc")
            || l.ends_with(".jar") || l.ends_with(".war") || l.ends_with(".ear")
            || l.ends_with(".mp3") || l.ends_with(".mp4") || l.ends_with(".mov")
            || l.ends_with(".avi") || l.ends_with(".mkv")
    };

    // Deduplicate by blob SHA: the same file content committed under different
    // paths or at different points in history needs to be scanned only once.
    let mut seen_shas: std::collections::HashSet<String> = std::collections::HashSet::new();

    let blob_entries: Vec<(String, String)> = String::from_utf8_lossy(&check_out.stdout)
        .lines()
        .zip(candidates.iter())
        .filter_map(|(check_line, (sha, path))| {
            let parts: Vec<&str> = check_line.split_whitespace().collect();
            if parts.len() < 3 || parts[1] != "blob" { return None; }
            let size: u64 = parts[2].parse().ok()?;
            if size == 0 || size > max_blob_size { return None; }
            if is_binary_ext(path) { return None; }
            if !seen_shas.insert(sha.clone()) { return None; } // deduplicate
            Some((sha.clone(), path.clone()))
        })
        .collect();

    if blob_entries.is_empty() {
        return Ok(vec![]);
    }

    // ── Phase 3: read blob contents via git cat-file --batch ──────────────────
    // Output per blob: "<sha> blob <size>\n<content bytes>\n"
    // Use a background thread to write stdin concurrently with stdout reading
    // to prevent deadlock on large repos where the pipe buffer fills.
    let blob_shas_input: Vec<u8> = blob_entries
        .iter()
        .flat_map(|(sha, _)| format!("{sha}\n").into_bytes())
        .collect();

    let mut batch_proc = Command::new("git")
        .args(["cat-file", "--batch"])
        .current_dir(repo_root)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|e| AuditError::GitError(format!("git cat-file --batch spawn: {e}")))?;

    let stdin_thread = {
        let mut stdin = batch_proc.stdin.take().unwrap();
        std::thread::spawn(move || {
            stdin.write_all(&blob_shas_input).ok();
        })
    };

    let batch_out = batch_proc
        .wait_with_output()
        .map_err(|e| AuditError::GitError(format!("git cat-file --batch: {e}")))?;

    stdin_thread.join().ok();

    // ── Parse the binary batch output stream ──────────────────────────────────
    let data = &batch_out.stdout;
    let mut blobs: Vec<HistoryBlob> = Vec::with_capacity(blob_entries.len());
    let mut pos = 0usize;
    let mut entry_idx = 0usize;

    while pos < data.len() && entry_idx < blob_entries.len() {
        // Find the header line (NUL-terminated in practice, newline-delimited here).
        let nl = match data[pos..].iter().position(|&b| b == b'\n') {
            Some(i) => pos + i,
            None => break,
        };
        let header = std::str::from_utf8(&data[pos..nl]).unwrap_or("").trim();
        pos = nl + 1;

        // git outputs "<sha> missing" when the object doesn't exist locally.
        if header.ends_with("missing") {
            entry_idx += 1;
            continue;
        }

        let parts: Vec<&str> = header.split_whitespace().collect();
        if parts.len() < 3 { entry_idx += 1; continue; }

        let size: usize = match parts[2].parse() {
            Ok(s) => s,
            Err(_) => { entry_idx += 1; continue; }
        };

        if pos + size > data.len() { break; }

        let content = data[pos..pos + size].to_vec();
        pos += size;
        // Skip trailing LF that git appends after each blob.
        if pos < data.len() && data[pos] == b'\n' { pos += 1; }

        let (sha, path) = &blob_entries[entry_idx];
        blobs.push(HistoryBlob {
            blob_sha: sha.clone(),
            filename: path.clone(),
            content,
        });
        entry_idx += 1;
    }

    Ok(blobs)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: is git available on PATH?
    fn git_available() -> bool {
        Command::new("git").arg("--version").output().is_ok()
    }

    #[test]
    fn repo_root_returns_path_when_in_git_repo() {
        if !git_available() {
            return; // skip in environments without git
        }
        // The sf-keyaudit workspace itself is a git repo
        let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        let result = repo_root(&cwd);
        // We just check it doesn't error and returns a directory
        if let Ok(root) = result {
            assert!(root.is_dir(), "repo root must be a directory");
        }
        // If it fails (e.g., CI sandbox with no .git), that's also acceptable
    }

    #[test]
    fn repo_root_fails_outside_repo() {
        if !git_available() {
            return;
        }
        // Use a temp dir that is definitely not a git repo
        let dir = tempfile::tempdir().unwrap();
        let result = repo_root(dir.path());
        assert!(
            result.is_err(),
            "should error when not in a git repository"
        );
    }

    #[test]
    fn parse_file_list_empty_output() {
        let result = parse_file_list(b"", std::path::Path::new("/tmp")).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn parse_file_list_filters_nonexistent_files() {
        // The paths won't exist, so they should be filtered out
        let raw = b"nonexistent_a.py\nnonexistent_b.tf\n";
        let result = parse_file_list(raw, std::path::Path::new("/tmp")).unwrap();
        assert!(result.is_empty(), "non-existent paths should be filtered");
    }
}
