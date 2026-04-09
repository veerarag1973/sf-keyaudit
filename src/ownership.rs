//! Code ownership enrichment for findings.
//!
//! Two data sources are supported:
//!
//! 1. **CODEOWNERS** — `.github/CODEOWNERS`, `CODEOWNERS`, or
//!    `docs/CODEOWNERS` (checked in that order) maps file-path globs to
//!    owning teams or individuals using the standard GitHub CODEOWNERS syntax.
//!
//! 2. **Git blame** — runs `git blame --porcelain -L <line>,<line>` on the
//!    finding's file to extract the last commit author and short SHA.
//!
//! Both sources are opt-in via `--owners` and require either a git repo or a
//! CODEOWNERS file to be present.  Failures are silently ignored so that the
//! feature degrades gracefully in environments without git.

use std::path::{Path, PathBuf};
use std::process::Command;

// ── CODEOWNERS ─────────────────────────────────────────────────────────────────

/// A single parsed CODEOWNERS rule.
#[derive(Debug, Clone)]
struct CodeownersRule {
    pattern: String,
    owners: Vec<String>,
}

/// In-memory lookup table built from a CODEOWNERS file.
pub struct CodeownersMap {
    /// Rules stored in *reverse* file order so that the last matching rule
    /// wins, which is the correct CODEOWNERS semantics.
    rules: Vec<CodeownersRule>,
}

impl CodeownersMap {
    /// Try to load CODEOWNERS from the standard locations under `repo_root`.
    ///
    /// Checks `.github/CODEOWNERS`, `CODEOWNERS`, `docs/CODEOWNERS` in order
    /// and uses the first file that exists.  Returns `None` when none is found.
    pub fn load(repo_root: &Path) -> Option<Self> {
        let candidates: [PathBuf; 3] = [
            repo_root.join(".github").join("CODEOWNERS"),
            repo_root.join("CODEOWNERS"),
            repo_root.join("docs").join("CODEOWNERS"),
        ];
        for path in &candidates {
            if path.exists() {
                if let Ok(content) = std::fs::read_to_string(path) {
                    tracing::debug!(path = %path.display(), "loaded CODEOWNERS");
                    return Some(Self::parse(&content));
                }
            }
        }
        None
    }

    fn parse(content: &str) -> Self {
        let mut rules: Vec<CodeownersRule> = content
            .lines()
            .filter_map(|line| {
                let trimmed = line.trim();
                if trimmed.is_empty() || trimmed.starts_with('#') {
                    return None;
                }
                let mut parts = trimmed.split_whitespace();
                let pattern = parts.next()?.to_string();
                let owners: Vec<String> = parts.map(|s| s.to_string()).collect();
                if owners.is_empty() {
                    return None;
                }
                Some(CodeownersRule { pattern, owners })
            })
            .collect();
        // Reverse so index 0 is the last rule (highest precedence).
        rules.reverse();
        Self { rules }
    }

    /// Return the owning teams / users for `file_path` (repo-relative, forward
    /// slashes).  Returns an empty `Vec` when no rule matches.
    pub fn owners_for(&self, file_path: &str) -> Vec<String> {
        let normalised = file_path.replace('\\', "/");
        for rule in &self.rules {
            if glob_matches(&rule.pattern, &normalised) {
                return rule.owners.clone();
            }
        }
        vec![]
    }
}

// ── Glob matching ─────────────────────────────────────────────────────────────

/// Entry point for CODEOWNERS-style glob matching.
///
/// Rules:
/// - If the pattern contains no `/`, match against the basename only.
/// - Leading `/` anchors the pattern to the repo root (stripped before matching).
/// - `*` matches any sequence of non-`/` characters.
/// - `**` matches any sequence including `/`.
fn glob_matches(pattern: &str, path: &str) -> bool {
    let p = pattern.trim_start_matches('/');

    // Directory prefix pattern (ends with `/`): matches all files under that dir.
    // e.g. "src/" matches "src/main.rs" and "src/lib/mod.rs".
    if p.ends_with('/') {
        return path.starts_with(p);
    }

    if !p.contains('/') {
        // Match basename only.
        let basename = path.split('/').next_back().unwrap_or(path);
        return simple_glob(p, basename);
    }
    simple_glob(p, path)
}

fn simple_glob(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    glob_rec(&p, &t, 0, 0)
}

fn glob_rec(p: &[char], t: &[char], pi: usize, ti: usize) -> bool {
    if pi == p.len() {
        return ti == t.len();
    }
    // `**` wildcard — match zero or more path segments.
    if pi + 1 < p.len() && p[pi] == '*' && p[pi + 1] == '*' {
        if glob_rec(p, t, pi + 2, ti) {
            return true;
        }
        if ti < t.len() {
            return glob_rec(p, t, pi, ti + 1);
        }
        return false;
    }
    // `*` wildcard — match any non-`/` sequence.
    if p[pi] == '*' {
        if glob_rec(p, t, pi + 1, ti) {
            return true;
        }
        if ti < t.len() && t[ti] != '/' {
            return glob_rec(p, t, pi, ti + 1);
        }
        return false;
    }
    // Literal or `?` (any single character).
    if ti < t.len() && (p[pi] == '?' || p[pi] == t[ti]) {
        return glob_rec(p, t, pi + 1, ti + 1);
    }
    false
}

// ── Git blame ─────────────────────────────────────────────────────────────────

/// Authorship information extracted from `git blame`.
#[derive(Debug, Clone)]
pub struct BlameInfo {
    /// Full author name from `git blame --porcelain`.
    pub author: String,
    /// Abbreviated (8-character) commit SHA.
    pub commit: String,
    /// ISO-8601 UTC timestamp of the commit.
    pub timestamp: Option<String>,
}

/// Run `git blame --porcelain -L <line>,<line>` and parse the result.
///
/// Returns `None` on any failure (git unavailable, file untracked, network
/// error, etc.) so callers can degrade gracefully.
pub fn blame_line(repo_root: &Path, relative_file: &str, line: usize) -> Option<BlameInfo> {
    if line == 0 {
        return None;
    }
    let range = format!("{line},{line}");
    let output = Command::new("git")
        .args(["blame", "--porcelain", "-L", &range, "--", relative_file])
        .current_dir(repo_root)
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }
    parse_blame_porcelain(&output.stdout)
}

fn parse_blame_porcelain(raw: &[u8]) -> Option<BlameInfo> {
    let text = String::from_utf8_lossy(raw);
    let mut commit = String::new();
    let mut author = String::new();
    let mut timestamp: Option<String> = None;

    for line in text.lines() {
        if commit.is_empty() && !line.starts_with('\t') {
            // First non-tab line: "<sha> <orig_line> <final_line> [<count>]"
            if let Some(sha) = line.split_whitespace().next() {
                commit = sha.to_string();
            }
        } else if let Some(a) = line.strip_prefix("author ") {
            author = a.trim().to_string();
        } else if let Some(t) = line.strip_prefix("author-time ") {
            if let Ok(secs) = t.trim().parse::<i64>() {
                if let Some(dt) = chrono::DateTime::from_timestamp(secs, 0) {
                    timestamp = Some(dt.format("%Y-%m-%dT%H:%M:%SZ").to_string());
                }
            }
        }
    }

    if commit.is_empty() || author.is_empty() {
        return None;
    }
    Some(BlameInfo {
        author,
        commit: commit[..commit.len().min(8)].to_string(),
        timestamp,
    })
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_map(content: &str) -> CodeownersMap {
        CodeownersMap::parse(content)
    }

    #[test]
    fn empty_file_returns_no_owners() {
        let m = make_map("");
        assert!(m.owners_for("src/main.rs").is_empty());
    }

    #[test]
    fn comment_lines_are_ignored() {
        let m = make_map("# this is a comment\n* @team\n");
        assert!(!m.owners_for("any/file.rs").is_empty());
    }

    #[test]
    fn wildcard_matches_any_file() {
        let m = make_map("* @default-team\n");
        assert_eq!(m.owners_for("src/lib.rs"), vec!["@default-team"]);
    }

    #[test]
    fn path_pattern_matches_file_in_directory() {
        let m = make_map("src/ @backend-team\n");
        assert_eq!(m.owners_for("src/main.rs"), vec!["@backend-team"]);
    }

    #[test]
    fn last_rule_wins() {
        let m = make_map("* @default-team\nsrc/ @src-team\n");
        // Last matching rule wins — "src/" is later and more specific.
        assert_eq!(m.owners_for("src/main.rs"), vec!["@src-team"]);
    }

    #[test]
    fn double_star_matches_nested_path() {
        let m = make_map("**/*.tf @infra-team\n");
        assert_eq!(m.owners_for("infra/prod/main.tf"), vec!["@infra-team"]);
        assert!(m.owners_for("src/main.rs").is_empty());
    }

    #[test]
    fn multiple_owners_returned() {
        let m = make_map("*.rs @alice @bob\n");
        let owners = m.owners_for("src/main.rs");
        assert_eq!(owners, vec!["@alice", "@bob"]);
    }

    #[test]
    fn glob_matches_basename_when_no_slash() {
        assert!(glob_matches("*.rs", "src/main.rs"));
        assert!(!glob_matches("*.rs", "src/main.py"));
    }

    #[test]
    fn glob_matches_exact_path() {
        assert!(glob_matches("src/config.rs", "src/config.rs"));
    }

    #[test]
    fn glob_matches_directory_prefix() {
        assert!(glob_matches("src/", "src/main.rs"));
        assert!(!glob_matches("src/", "lib/main.rs"));
    }

    #[test]
    fn parse_blame_porcelain_extracts_author() {
        let raw = b"abc12345 1 1 1\nauthor Jane Doe\nauthor-time 1700000000\n\tcode line\n";
        let info = parse_blame_porcelain(raw).unwrap();
        assert_eq!(info.author, "Jane Doe");
        assert_eq!(info.commit, "abc12345");
        assert!(info.timestamp.is_some());
    }

    #[test]
    fn parse_blame_porcelain_empty_returns_none() {
        assert!(parse_blame_porcelain(b"").is_none());
    }
}
