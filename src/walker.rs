//! Directory walker with respect for `.gitignore` and `.sfignore`.
//!
//! Uses the `ignore` crate (the walking engine behind `ripgrep`) for fast,
//! parallel-friendly traversal that honours all standard ignore files.
//!
//! **Memory model:** the walker returns only paths and non-fatal warnings.
//! File contents are read inside the rayon worker in `main`, so only one
//! file worth of data is live per CPU thread rather than all files at once.

use crate::scanner::DEFAULT_MAX_FILE_SIZE;
use std::io::Write as _;
use std::path::{Path, PathBuf};

/// Archive file extensions that can be expanded when `scan_archives` is enabled.
const ARCHIVE_EXTS: &[&str] = &["zip", "tar", "gz", "tgz", "bz2", "xz"];

fn is_archive_path(path: &Path) -> bool {
    if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
        ARCHIVE_EXTS.contains(&ext.to_lowercase().as_str())
    } else {
        false
    }
}

/// Configuration for the directory walker.
#[derive(Debug, Clone)]
pub struct WalkConfig {
    /// Maximum file size in bytes.  Files larger than this are skipped.
    pub max_file_size: u64,
    /// Maximum directory depth.  `None` means unlimited.
    pub max_depth: Option<usize>,
    /// Whether to disable `.gitignore` / `.sfignore` exclusions.
    pub no_ignore: bool,
    /// Paths to gitignore-style ignore files supplied via `--ignore-file`.
    pub extra_ignore_files: Vec<String>,
    /// Follow symbolic links during traversal.  Defaults to `false`.
    pub follow_links: bool,
    /// Additional gitignore-style patterns (from `project_config.ignore_patterns`).
    /// These are written to a temporary file and passed to the ignore builder.
    pub extra_patterns: Vec<String>,
    /// Gitignore-style patterns that whitelist files for scanning
    /// (from `project_config.include_patterns`).  When non-empty, only files
    /// whose path matches at least one pattern are yielded.
    pub include_patterns: Vec<String>,
    /// Whether archive files (.zip, .tar, .tar.gz, .tgz) should be yielded
    /// as scannable entries rather than being silently skipped.
    pub scan_archives: bool,
}

impl Default for WalkConfig {
    fn default() -> Self {
        Self {
            max_file_size: DEFAULT_MAX_FILE_SIZE,
            max_depth: None,
            no_ignore: false,
            extra_ignore_files: vec![],
            follow_links: false,
            extra_patterns: vec![],
            include_patterns: vec![],
            scan_archives: false,
        }
    }
}

/// A file path discovered during the walk.
///
/// `warning` is populated for skipped files (size, stat failures, etc.).
/// When `warning` is `Some` the entry should be emitted to stderr and
/// skipped; `path` may still be set for context.
#[derive(Debug)]
pub struct WalkEntry {
    pub path: PathBuf,
    /// Non-fatal warning to emit to stderr.  `None` means the file is scannable.
    pub warning: Option<String>,
}

// ── public surface ────────────────────────────────────────────────────────────

/// Walk `root` returning one [`WalkEntry`] per discovered file (or per warning).
///
/// File *contents are not read here*; that happens inside the rayon worker so
/// each thread holds at most one file in memory at a time.
pub fn walk(root: &Path, config: &WalkConfig) -> Vec<WalkEntry> {
    // Always-excluded directories regardless of ignore settings.
    const EXCLUDED_DIRS: &[&str] = &[
        ".git",
        "node_modules",
        "target",
        "dist",
        ".venv",
        "venv",
        "vendor",
        "__pycache__",
        ".mypy_cache",
        ".pytest_cache",
        "build",
        ".next",
        ".nuxt",
    ];

    let mut builder = ignore::WalkBuilder::new(root);
    builder
        .hidden(false) // scan hidden files (except .git which we skip below)
        .git_ignore(!config.no_ignore)
        .ignore(!config.no_ignore)
        .git_global(!config.no_ignore)
        .git_exclude(!config.no_ignore)
        .follow_links(config.follow_links)
        .same_file_system(!config.follow_links); // prevent escaping the FS when not following links

    if let Some(depth) = config.max_depth {
        builder.max_depth(Some(depth));
    }

    // Extra ignore files supplied via --ignore-file.
    for path in &config.extra_ignore_files {
        builder.add_ignore(path);
    }

    // Extra gitignore-style patterns from project config — write to a temp
    // file and register it with the builder.  We keep _pattern_tmpfile alive
    // in scope until after builder.build() has finished iterating.
    let _pattern_tmpfile: Option<tempfile::NamedTempFile> = if config.extra_patterns.is_empty() {
        None
    } else {
        match tempfile::Builder::new()
            .prefix(".sfkeyaudit-ignore")
            .suffix(".gitignore")
            .tempfile()
        {
            Ok(mut f) => {
                for pat in &config.extra_patterns {
                    let _ = writeln!(f, "{pat}");
                }
                let _ = f.flush();
                builder.add_ignore(f.path());
                Some(f)
            }
            Err(_) => None, // silently fall back — patterns not applied
        }
    };

    // Also look for .sfignore in the root.
    let sfignore = root.join(".sfignore");
    if sfignore.exists() {
        builder.add_ignore(&sfignore);
    }

    let mut entries = Vec::new();

    for entry_result in builder.build() {
        let entry = match entry_result {
            Ok(e) => e,
            Err(err) => {
                entries.push(WalkEntry {
                    path: PathBuf::new(),
                    warning: Some(format!("walk error: {err}")),
                });
                continue;
            }
        };

        let path = entry.path().to_path_buf();

        // Skip directories.
        if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            continue;
        }

        // Skip always-excluded directories by checking path components.
        if path_contains_excluded_dir(&path, EXCLUDED_DIRS) {
            continue;
        }

        // File size check — use entry metadata to avoid an extra stat(2).
        let metadata = match entry.metadata() {
            Ok(m) => m,
            Err(err) => {
                entries.push(WalkEntry {
                    path,
                    warning: Some(format!("cannot stat: {err}")),
                });
                continue;
            }
        };

        if metadata.len() > config.max_file_size {
            entries.push(WalkEntry {
                path: path.clone(),
                warning: Some(format!(
                    "skipping {} ({} bytes > {} byte limit)",
                    path.display(),
                    metadata.len(),
                    config.max_file_size
                )),
            });
            continue;
        }

        // Archive files are only returned when scan_archives is enabled.
        // Without the flag they are silently skipped so normal scans are not
        // cluttered with binary archive entries.
        if is_archive_path(&path) && !config.scan_archives {
            continue;
        }

        // File is within limits — emit a scannable entry (no content yet).
        entries.push(WalkEntry { path, warning: None });
    }

    // ── Include-pattern filtering ─────────────────────────────────────────────
    // When include_patterns is non-empty, keep only entries whose path matches
    // at least one pattern (gitignore-style).  Warning entries are always kept
    // so they can be reported to stderr regardless of include filtering.
    if !config.include_patterns.is_empty() {
        let mut gb = ignore::gitignore::GitignoreBuilder::new(root);
        for pat in &config.include_patterns {
            let _ = gb.add_line(None, pat);
        }
        if let Ok(matcher) = gb.build() {
            entries.retain(|e| {
                // Always keep warning entries.
                if e.warning.is_some() {
                    return true;
                }
                // Keep the entry only if the path matches a pattern.
                matcher.matched(&e.path, false).is_ignore()
            });
        }
    }

    entries
}

/// Single-file entry point.  Returns one entry for the file (or a warning).
pub fn walk_single_file(path: &Path, config: &WalkConfig) -> Vec<WalkEntry> {
    if !path.is_file() {
        return vec![WalkEntry {
            path: path.to_path_buf(),
            warning: Some(format!("{} is not a file", path.display())),
        }];
    }

    let metadata = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(err) => {
            return vec![WalkEntry {
                path: path.to_path_buf(),
                warning: Some(format!("cannot stat {}: {err}", path.display())),
            }];
        }
    };

    if metadata.len() > config.max_file_size {
        return vec![WalkEntry {
            path: path.to_path_buf(),
            warning: Some(format!(
                "skipping {} ({} bytes > {} byte limit)",
                path.display(),
                metadata.len(),
                config.max_file_size
            )),
        }];
    }

    vec![WalkEntry { path: path.to_path_buf(), warning: None }]
}

// ── private helpers ───────────────────────────────────────────────────────────

fn path_contains_excluded_dir(path: &Path, excluded: &[&str]) -> bool {
    path.components().any(|c| {
        if let std::path::Component::Normal(name) = c {
            excluded.iter().any(|e| name == std::ffi::OsStr::new(e))
        } else {
            false
        }
    })
}

// ── public helper: read one file inside a rayon worker ───────────────────────

/// Read the content of a single file for scanning.
///
/// Returns `(content, warning)`:
/// - Binary files: `(None, None)` — silent skip.
/// - Valid UTF-8: `(Some(text), None)`.
/// - Invalid UTF-8: `(Some(lossy_text), Some(warning))`.
/// - I/O error: `(None, Some(error_message))`.
#[allow(dead_code)]
pub fn read_file_content_lossy(path: &Path) -> (Option<String>, Option<String>) {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(err) => return (None, Some(format!("cannot read {}: {err}", path.display()))),
    };

    if crate::scanner::is_binary(&bytes) {
        return (None, None); // silent skip
    }

    match std::str::from_utf8(&bytes) {
        Ok(s) => (Some(s.to_string()), None),
        Err(_) => {
            let lossy = String::from_utf8_lossy(&bytes).into_owned();
            let warn = format!("{}: invalid UTF-8 sequences replaced", path.display());
            (Some(lossy), Some(warn))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn make_dir() -> TempDir {
        tempfile::tempdir().unwrap()
    }

    fn config() -> WalkConfig {
        WalkConfig::default()
    }

    // ── path_contains_excluded_dir ───────────────────────────────────────────

    #[test]
    fn excludes_node_modules_path() {
        let path = Path::new("/project/node_modules/lodash/index.js");
        assert!(path_contains_excluded_dir(path, &["node_modules"]));
    }

    #[test]
    fn excludes_git_path() {
        let path = Path::new("/project/.git/COMMIT_EDITMSG");
        assert!(path_contains_excluded_dir(path, &[".git"]));
    }

    #[test]
    fn does_not_exclude_regular_path() {
        let path = Path::new("/project/src/main.rs");
        assert!(!path_contains_excluded_dir(path, &["node_modules", ".git"]));
    }

    // ── walk returns entries ─────────────────────────────────────────────────

    #[test]
    fn walks_basic_directory() {
        let dir = make_dir();
        fs::write(dir.path().join("hello.py"), b"print('hello')").unwrap();
        let entries = walk(dir.path(), &config());
        let found: Vec<_> = entries.iter().filter(|e| e.warning.is_none()).collect();
        assert!(!found.is_empty(), "should find at least one file");
    }

    #[test]
    fn skips_files_over_size_limit() {
        let dir = make_dir();
        let big = vec![b'A'; 100];
        fs::write(dir.path().join("big.txt"), &big).unwrap();
        let mut cfg = config();
        cfg.max_file_size = 50;
        let entries = walk(dir.path(), &cfg);
        let warned = entries.iter().any(|e| {
            e.path.ends_with("big.txt")
                && e.warning.as_deref().unwrap_or("").contains("skipping")
        });
        assert!(warned, "oversized file should generate a warning");
    }

    #[test]
    fn skips_git_directory() {
        let dir = make_dir();
        fs::create_dir(dir.path().join(".git")).unwrap();
        fs::write(
            dir.path().join(".git").join("secret.txt"),
            b"sk-proj-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ).unwrap();
        let entries = walk(dir.path(), &config());
        let git_found = entries.iter().any(|e| e.path.to_string_lossy().contains(".git"));
        assert!(!git_found, ".git directory must be excluded");
    }

    #[test]
    fn skips_node_modules() {
        let dir = make_dir();
        fs::create_dir_all(dir.path().join("node_modules/pkg")).unwrap();
        fs::write(
            dir.path().join("node_modules/pkg/index.js"),
            b"const key = 'AKIAIOSFODNN7EXAMPLE';",
        ).unwrap();
        let entries = walk(dir.path(), &config());
        let nm_found = entries.iter().any(|e| e.path.to_string_lossy().contains("node_modules"));
        assert!(!nm_found, "node_modules must be excluded");
    }

    // ── max_depth ────────────────────────────────────────────────────────────

    #[test]
    fn max_depth_limits_traversal() {
        let dir = make_dir();
        fs::create_dir_all(dir.path().join("a/b/c")).unwrap();
        fs::write(dir.path().join("top.py"), b"x=1").unwrap();
        fs::write(dir.path().join("a/mid.py"), b"x=1").unwrap();
        fs::write(dir.path().join("a/b/c/deep.py"), b"x=1").unwrap();

        let mut cfg = config();
        cfg.max_depth = Some(1);

        let entries = walk(dir.path(), &cfg);
        let paths: Vec<_> = entries
            .iter()
            .filter(|e| e.warning.is_none())
            .map(|e| e.path.file_name().unwrap().to_string_lossy().into_owned())
            .collect();

        assert!(paths.contains(&"top.py".to_string()));
        assert!(!paths.contains(&"deep.py".to_string()));
    }

    // ── walk_single_file ─────────────────────────────────────────────────────

    #[test]
    fn single_file_returns_no_warning() {
        let dir = make_dir();
        let f = dir.path().join("key.txt");
        fs::write(&f, b"AKIAIOSFODNN7EXAMPLE").unwrap();
        let entries = walk_single_file(&f, &config());
        assert_eq!(entries.len(), 1);
        assert!(entries[0].warning.is_none());
    }

    #[test]
    fn single_file_missing_returns_warning() {
        let entries = walk_single_file(Path::new("/no/such/file.txt"), &config());
        assert_eq!(entries.len(), 1);
        assert!(entries[0].warning.is_some());
    }

    // ── binary detection via read_file_content_lossy ─────────────────────────

    #[test]
    fn binary_file_returns_none_content() {
        let dir = make_dir();
        let f = dir.path().join("data.bin");
        fs::write(&f, b"\x00\x01\x02").unwrap();
        let (content, warn) = read_file_content_lossy(&f);
        assert!(content.is_none(), "binary file should yield None content");
        assert!(warn.is_none(), "binary skip is silent");
    }

    // ── extra_ignore_files ───────────────────────────────────────────────────

    #[test]
    fn extra_ignore_files_excludes_matching_files() {
        let dir = make_dir();
        fs::write(dir.path().join("skip_this.log"), b"SECRET=abc").unwrap();
        fs::write(dir.path().join("keep.py"), b"x=1").unwrap();
        let ignore_file = dir.path().join(".custom_ignore");
        fs::write(&ignore_file, b"*.log\n").unwrap();
        let mut cfg = config();
        cfg.extra_ignore_files = vec![ignore_file.to_string_lossy().into_owned()];
        let entries = walk(dir.path(), &cfg);
        let log_found = entries.iter().any(|e| e.path.to_string_lossy().ends_with(".log") && e.warning.is_none());
        assert!(!log_found, "*.log should be excluded via ignore file");
        let py_found = entries.iter().any(|e| e.path.to_string_lossy().ends_with(".py") && e.warning.is_none());
        assert!(py_found, ".py file should still be scanned");
    }

    // ── .sfignore support ────────────────────────────────────────────────────

    #[test]
    fn sfignore_file_excludes_matching_files() {
        let dir = make_dir();
        fs::write(dir.path().join(".sfignore"), b"ignored_secrets.txt\n").unwrap();
        fs::write(dir.path().join("ignored_secrets.txt"), b"KEY=super_secret").unwrap();
        fs::write(dir.path().join("normal.py"), b"x=1").unwrap();
        let entries = walk(dir.path(), &config());
        let ignored = entries.iter().any(|e| e.path.to_string_lossy().ends_with("ignored_secrets.txt") && e.warning.is_none());
        assert!(!ignored, "file listed in .sfignore must be excluded");
        let normal = entries.iter().any(|e| e.path.to_string_lossy().ends_with("normal.py") && e.warning.is_none());
        assert!(normal, "non-ignored file must still be found");
    }

    // ── invalid UTF-8 via read_file_content_lossy ────────────────────────────

    #[test]
    fn invalid_utf8_file_produces_lossy_content_with_warning() {
        let dir = make_dir();
        let mut content = b"hello world ".to_vec();
        content.extend_from_slice(&[0xFF, 0xFE]);
        content.extend_from_slice(b" end");
        fs::write(dir.path().join("weird.txt"), &content).unwrap();
        let f = dir.path().join("weird.txt");
        let (text, warn) = read_file_content_lossy(&f);
        // 0xFF is not a null byte, so it's not detected as binary.
        // The content should be returned with a warning.
        assert!(text.is_some(), "lossy content should be returned");
        assert!(warn.is_some(), "invalid UTF-8 should produce a warning");
    }

    // ── single file over size limit ──────────────────────────────────────────

    #[test]
    fn single_file_over_size_limit_returns_warning() {
        let dir = make_dir();
        let data = vec![b'A'; 200];
        let f = dir.path().join("big.txt");
        fs::write(&f, &data).unwrap();
        let mut cfg = config();
        cfg.max_file_size = 100;
        let entries = walk_single_file(&f, &cfg);
        assert_eq!(entries.len(), 1);
        assert!(entries[0].warning.as_deref().unwrap_or("").contains("skipping"));
    }

    // ── follow_links off by default ───────────────────────────────────────────

    #[test]
    fn follow_links_defaults_to_false() {
        let cfg = WalkConfig::default();
        assert!(!cfg.follow_links, "follow_links must default to false");
    }
}
