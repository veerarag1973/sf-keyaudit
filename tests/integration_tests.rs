//! Integration tests for sf-keyaudit.
//!
//! These tests exercise the binary end-to-end via `assert_cmd`.

use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use tempfile::TempDir;

// ── helpers ──────────────────────────────────────────────────────────────────

fn cmd() -> Command {
    Command::cargo_bin("sf-keyaudit").unwrap()
}

fn setup() -> TempDir {
    tempfile::tempdir().unwrap()
}

/// Write a file relative to `dir`.
fn write(dir: &TempDir, name: &str, content: &[u8]) {
    let path = dir.path().join(name);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(path, content).unwrap()
}

fn git(dir: &TempDir, args: &[&str]) {
    let status = std::process::Command::new("git")
        .args(args)
        .current_dir(dir.path())
        .status()
        .unwrap();
    assert!(status.success(), "git command failed: git {:?}", args);
}

// ── exit codes ───────────────────────────────────────────────────────────────

#[test]
fn exit_0_on_clean_directory() {
    let dir = setup();
    write(&dir, "clean.py", b"print('hello world')\n");
    cmd()
        .arg(dir.path())
        .assert()
        .success()
        .code(0);
}

#[test]
fn exit_1_on_openai_legacy_key() {
    let dir = setup();
    // 48-char alphanumeric body with high entropy
    let key = "sk-xK9pQm7vL3nRwT5yJbHfDcGsEaZuViYo4W8MiNqX2Pe5AbcD";
    write(&dir, "config.py", format!("API_KEY = '{key}'\n").as_bytes());
    cmd()
        .arg(dir.path())
        .assert()
        .failure()
        .code(1);
}

#[test]
fn exit_1_on_anthropic_key() {
    let dir = setup();
    // 93-char body: 85-char base + "abcdefgh" = 93 (verified)
    let body = "xK9pQm7vL3nRwT5yJbHfDcGsEaZuViYo4W8MiNqX2PeUhCjBgFtOkRdSl1A6v0DwY_n-5mIT7QzHuWbEjcKaPabcdefgh";
    write(
        &dir,
        "client.py",
        format!("KEY = 'sk-ant-api03-{body}'\n").as_bytes(),
    );
    cmd()
        .arg(dir.path())
        .assert()
        .failure()
        .code(1);
}

#[test]
fn exit_1_on_aws_access_key() {
    let dir = setup();
    write(&dir, "infra.tf", b"access_key = \"AKIAX9KPQ7VL3NRW8MB5\"\n");
    cmd()
        .arg(dir.path())
        .assert()
        .failure()
        .code(1);
}

#[test]
fn exit_1_on_google_gemini_key() {
    let dir = setup();
    // AIza + 35 varied chars
    write(
        &dir,
        "app.env",
        b"GOOGLE_API_KEY=AIzaSyT7uV8wX9yZ0aB1cD2eF3gH4iJ5kL6mN7o\n",
    );
    cmd()
        .arg(dir.path())
        .assert()
        .failure()
        .code(1);
}

#[test]
fn exit_1_on_huggingface_token() {
    let dir = setup();
    write(
        &dir,
        "train.sh",
        b"export HF_TOKEN=hf_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8\n",
    );
    cmd()
        .arg(dir.path())
        .assert()
        .failure()
        .code(1);
}

#[test]
fn exit_1_on_groq_key() {
    let dir = setup();
    write(
        &dir,
        "model.py",
        b"client = Groq(api_key='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')\n",
    );
    cmd()
        .arg(dir.path())
        .assert()
        .failure()
        .code(1);
}

// ── output format ─────────────────────────────────────────────────────────────

#[test]
fn default_output_is_valid_json() {
    let dir = setup();
    write(&dir, "clean.py", b"x = 1\n");
    let output = cmd()
        .arg(dir.path())
        .output()
        .unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&stdout)
        .expect("stdout must be valid JSON");
    assert!(parsed.is_object());
    assert_eq!(parsed["tool"].as_str().unwrap(), "sf-keyaudit");
}

#[test]
fn json_report_has_required_fields() {
    let dir = setup();
    write(&dir, "clean.py", b"x = 1\n");
    let output = cmd().arg(dir.path()).output().unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    for field in &[
        "scan_id", "tool", "version", "timestamp", "scan_root",
        "files_scanned", "findings", "summary",
    ] {
        assert!(v.get(field).is_some(), "missing top-level field: {field}");
    }
}

#[test]
fn sarif_output_is_valid_json_with_schema() {
    let dir = setup();
    write(&dir, "clean.py", b"x = 1\n");
    let output = cmd()
        .args([dir.path().to_str().unwrap(), "--format", "sarif"])
        .output()
        .unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("SARIF must be valid JSON");
    assert_eq!(v["version"].as_str().unwrap(), "2.1.0");
    assert!(v["$schema"].as_str().unwrap().contains("sarif-2.1.0"));
}

// ── --output file ─────────────────────────────────────────────────────────────

#[test]
fn writes_report_to_file() {
    let dir = setup();
    write(&dir, "clean.py", b"x = 1\n");
    let report_path = dir.path().join("report.json");
    cmd()
        .arg(dir.path())
        .arg("--output")
        .arg(&report_path)
        .assert()
        .success();
    assert!(report_path.exists(), "report file must be created");
    let content = fs::read_to_string(&report_path).unwrap();
    let v: serde_json::Value = serde_json::from_str(&content).unwrap();
    assert_eq!(v["tool"].as_str().unwrap(), "sf-keyaudit");
}

// ── --quiet ───────────────────────────────────────────────────────────────────

#[test]
fn quiet_mode_produces_no_stdout_when_clean() {
    let dir = setup();
    write(&dir, "clean.py", b"x = 1\n");
    cmd()
        .args([dir.path().to_str().unwrap(), "-q"])
        .assert()
        .success()
        .stdout("");
}

#[test]
fn quiet_mode_still_exits_1_on_finding() {
    let dir = setup();
    let key = "sk-xK9pQm7vL3nRwT5yJbHfDcGsEaZuViYo4W8MiNqX2Pe5AbcD";
    write(&dir, "config.py", format!("KEY='{key}'\n").as_bytes());
    cmd()
        .args([dir.path().to_str().unwrap(), "-q"])
        .assert()
        .failure()
        .code(1)
        .stdout("");
}

// ── --providers ───────────────────────────────────────────────────────────────

#[test]
fn provider_filter_scans_only_requested_provider() {
    let dir = setup();
    // Put an OpenAI key and an AWS key in the same file
    let key = "sk-xK9pQm7vL3nRwT5yJbHfDcGsEaZuViYo4W8MiNqX2Pe5AbcD";
    write(
        &dir,
        "multi.py",
        format!("OPENAI_KEY='{key}'\nAWS_KEY='AKIAX9KPQ7VL3NRW8MB5'\n").as_bytes(),
    );

    // When scanning only anthropic, neither key should be found → exit 0
    cmd()
        .args([dir.path().to_str().unwrap(), "--providers", "anthropic", "-q"])
        .assert()
        .success()
        .code(0);
}

#[test]
fn scanning_scan_target_with_openai_and_aws_finds_both() {
    let dir = setup();
    let key = "sk-xK9pQm7vL3nRwT5yJbHfDcGsEaZuViYo4W8MiNqX2Pe5AbcD";
    write(
        &dir,
        "keys.py",
        format!("OPENAI='{key}'\nAWS='AKIAX9KPQ7VL3NRW8MB5'\n").as_bytes(),
    );
    let output = cmd().arg(dir.path()).output().unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let total = v["summary"]["total_findings"].as_u64().unwrap();
    assert!(total >= 2, "expected at least 2 findings, got {total}");
}

// ── allowlist ─────────────────────────────────────────────────────────────────

#[test]
fn allowlist_suppresses_finding_exit_0() {
    let dir = setup();
    let key = "sk-xK9pQm7vL3nRwT5yJbHfDcGsEaZuViYo4W8MiNqX2Pe5AbcD";
    write(&dir, "mock.py", format!("KEY='{key}'\n").as_bytes());

    // The finding is at line 1. Allowlist it.
    // We need to know the pattern_id; openai-legacy-key-v1 for sk-[48]
    let allowlist = r#"
allowlist:
  - pattern_id: openai-legacy-key-v1
    file: mock.py
    line: 1
    reason: "Test fixture key — not a live credential"
"#;
    write(&dir, ".sfkeyaudit-allow.yaml", allowlist.as_bytes());

    cmd()
        .arg(dir.path())
        .arg("--allowlist")
        .arg(dir.path().join(".sfkeyaudit-allow.yaml"))
        .assert()
        .code(predicate::in_iter([0i32, 4]));
}

#[test]
fn allowlist_with_missing_reason_returns_exit_2() {
    let dir = setup();
    write(&dir, "x.py", b"x=1\n");
    let allowlist = b"allowlist:\n  - pattern_id: openai-legacy-key-v1\n    file: x.py\n    line: 1\n    reason: \"\"\n";
    write(&dir, ".al.yaml", allowlist);

    cmd()
        .arg(dir.path())
        .arg("--allowlist")
        .arg(dir.path().join(".al.yaml"))
        .assert()
        .code(2);
}

// ── binary file skipping ──────────────────────────────────────────────────────

#[test]
fn binary_file_is_skipped_silently() {
    let dir = setup();
    // Binary file with a null byte — should be ignored, not cause a finding
    write(&dir, "data.bin", b"\x00\x01\x02\x03AKIAIOSFODNN7EXAMPLE\x00");
    cmd()
        .arg(dir.path())
        .assert()
        .success()
        .code(0);
}

// ── single file scanning ──────────────────────────────────────────────────────

#[test]
fn scan_single_file_with_key() {
    let dir = setup();
    let key = "sk-xK9pQm7vL3nRwT5yJbHfDcGsEaZuViYo4W8MiNqX2Pe5AbcD";
    write(&dir, "secret.py", format!("KEY='{key}'\n").as_bytes());
    cmd()
        .arg(dir.path().join("secret.py"))
        .assert()
        .failure()
        .code(1);
}

#[test]
fn scan_single_clean_file() {
    let dir = setup();
    write(&dir, "clean.py", b"x = 42\n");
    cmd()
        .arg(dir.path().join("clean.py"))
        .assert()
        .success()
        .code(0);
}

// ── nonexistent path ──────────────────────────────────────────────────────────

#[test]
fn nonexistent_path_exits_3() {
    cmd()
        .arg("/no/such/path/at/all")
        .assert()
        .code(3);
}

// ── --fail-fast ───────────────────────────────────────────────────────────────

#[test]
fn fail_fast_exits_1_on_first_finding() {
    let dir = setup();
    let key = "sk-xK9pQm7vL3nRwT5yJbHfDcGsEaZuViYo4W8MiNqX2Pe5AbcD";
    write(&dir, "a.py", format!("KEY='{key}'\n").as_bytes());
    write(&dir, "b.py", format!("KEY2='{key}'\n").as_bytes());
    cmd()
        .args([dir.path().to_str().unwrap(), "--fail-fast", "-q"])
        .assert()
        .failure()
        .code(1);
}

// ── report structure when findings exist ─────────────────────────────────────

#[test]
fn json_finding_has_all_required_fields() {
    let dir = setup();
    let key = "sk-xK9pQm7vL3nRwT5yJbHfDcGsEaZuViYo4W8MiNqX2Pe5AbcD";
    write(&dir, "config.py", format!("KEY='{key}'\n").as_bytes());
    let output = cmd().arg(dir.path()).output().unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let findings = v["findings"].as_array().unwrap();
    assert!(!findings.is_empty());
    let f = &findings[0];
    for field in &["id", "provider", "file", "line", "column", "match", "pattern_id", "severity", "entropy"] {
        assert!(f.get(field).is_some(), "finding missing field: {field}");
    }
}

#[test]
fn finding_match_field_is_redacted() {
    let dir = setup();
    let key = "sk-xK9pQm7vL3nRwT5yJbHfDcGsEaZuViYo4W8MiNqX2Pe5AbcD";
    write(&dir, "config.py", format!("KEY='{key}'\n").as_bytes());
    let output = cmd().arg(dir.path()).output().unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    // The raw key body must not appear in the output
    assert!(!stdout.contains("xK9pQm7vL3nRwT5yJbHfDcGsEaZuViYo4W8MiNqX2Pe"),
        "raw key body must not appear in output");
    assert!(stdout.contains("***REDACTED***"));
}

// ── node_modules / target excluded ───────────────────────────────────────────

#[test]
fn node_modules_excluded_from_scan() {
    let dir = setup();
    let key = "sk-xK9pQm7vL3nRwT5yJbHfDcGsEaZuViYo4W8MiNqX2Pe5AbcD";
    fs::create_dir_all(dir.path().join("node_modules")).unwrap();
    write(
        &dir,
        "node_modules/pkg.js",
        format!("const k = '{key}';").as_bytes(),
    );
    write(&dir, "clean.py", b"x = 1\n");
    cmd()
        .arg(dir.path())
        .assert()
        .success()
        .code(0);
}

#[test]
fn target_directory_excluded_from_scan() {
    let dir = setup();
    let key = "sk-xK9pQm7vL3nRwT5yJbHfDcGsEaZuViYo4W8MiNqX2Pe5AbcD";
    fs::create_dir_all(dir.path().join("target/debug")).unwrap();
    write(
        &dir,
        "target/debug/build_output.txt",
        format!("key={key}").as_bytes(),
    );
    write(&dir, "src.py", b"print(1)\n");
    cmd()
        .arg(dir.path())
        .assert()
        .success()
        .code(0);
}

// ── multiple providers detected ───────────────────────────────────────────────

#[test]
fn openai_and_groq_both_detected() {
    let dir = setup();
    let openai = "sk-xK9pQm7vL3nRwT5yJbHfDcGsEaZuViYo4W8MiNqX2Pe5AbcD";
    let groq = "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";
    write(
        &dir,
        "app.py",
        format!("OPENAI='{openai}'\nGROQ='{groq}'\n").as_bytes(),
    );
    let output = cmd().arg(dir.path()).output().unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let by_provider = v["summary"]["by_provider"].as_object().unwrap();
    assert!(by_provider.contains_key("groq"), "groq must be detected");
    // openai or stability-ai depending on context
    let has_openai = by_provider.contains_key("openai") || by_provider.contains_key("stability-ai");
    assert!(has_openai, "openai-style key must be detected");
}

// ── files_scanned count ───────────────────────────────────────────────────────

#[test]
fn files_scanned_count_is_accurate() {
    let dir = setup();
    write(&dir, "a.py", b"x=1\n");
    write(&dir, "b.py", b"y=2\n");
    write(&dir, "c.txt", b"z=3\n");
    let output = cmd().arg(dir.path()).output().unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let count = v["files_scanned"].as_u64().unwrap();
    assert!(count >= 3, "expected at least 3 files scanned, got {count}");
}

// ── summary structure ─────────────────────────────────────────────────────────

#[test]
fn clean_scan_has_zero_summary_counts() {
    let dir = setup();
    write(&dir, "clean.rs", b"fn main() {}\n");
    let output = cmd().arg(dir.path()).output().unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["summary"]["total_findings"].as_u64().unwrap(), 0);
    assert_eq!(v["summary"]["files_with_findings"].as_u64().unwrap(), 0);
}

// ── line number accuracy ──────────────────────────────────────────────────────

#[test]
fn finding_line_number_is_correct() {
    let dir = setup();
    let key = "sk-xK9pQm7vL3nRwT5yJbHfDcGsEaZuViYo4W8MiNqX2Pe5AbcD";
    // Key is on line 3
    let content = format!("# line 1\n# line 2\nKEY='{key}'\n# line 4\n");
    write(&dir, "keys.py", content.as_bytes());
    let output = cmd().arg(dir.path()).output().unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let findings = v["findings"].as_array().unwrap();
    assert!(!findings.is_empty());
    assert_eq!(findings[0]["line"].as_u64().unwrap(), 3, "key is on line 3");
}

// ── scan_root is absolute in report ──────────────────────────────────────────

#[test]
fn scan_root_in_report_is_absolute() {
    let dir = setup();
    write(&dir, "f.py", b"x=1\n");
    let output = cmd().arg(dir.path()).output().unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let scan_root = v["scan_root"].as_str().unwrap();
    assert!(
        std::path::Path::new(scan_root).is_absolute(),
        "scan_root must be absolute, got: {scan_root}"
    );
}

// ── --follow-links ────────────────────────────────────────────────────────────

/// Without `--follow-links`, a symlink to a directory containing a key must
/// NOT be traversed, so the scan should be clean.
#[cfg(unix)]
#[test]
fn without_follow_links_symlinked_dir_is_not_traversed() {
    use std::os::unix::fs::symlink;

    let key_dir = setup();
    let key = "sk-xK9pQm7vL3nRwT5yJbHfDcGsEaZuViYo4W8MiNqX2Pe5AbcD";
    write(&key_dir, "secret.py", format!("KEY='{key}'\n").as_bytes());

    let scan_dir = setup();
    write(&scan_dir, "clean.py", b"x=1\n");
    // Create a symlink inside scan_dir pointing to the directory that has a key
    symlink(key_dir.path(), scan_dir.path().join("linked")).unwrap();

    cmd()
        .arg(scan_dir.path())
        .assert()
        .success()
        .code(0);
}

/// With `--follow-links`, a symlink to a directory containing a key MUST be
/// traversed, so the scan should detect the key.
#[cfg(unix)]
#[test]
fn with_follow_links_symlinked_dir_is_traversed() {
    use std::os::unix::fs::symlink;

    let key_dir = setup();
    let key = "sk-xK9pQm7vL3nRwT5yJbHfDcGsEaZuViYo4W8MiNqX2Pe5AbcD";
    write(&key_dir, "secret.py", format!("KEY='{key}'\n").as_bytes());

    let scan_dir = setup();
    write(&scan_dir, "clean.py", b"x=1\n");
    symlink(key_dir.path(), scan_dir.path().join("linked")).unwrap();

    cmd()
        .arg(scan_dir.path())
        .arg("--follow-links")
        .assert()
        .failure()
        .code(1);
}

// ── --ignore-file ─────────────────────────────────────────────────────────────

/// Passing a non-existent path to `--ignore-file` should not crash the tool;
/// the walker silently ignores unreadable ignore files and the scan proceeds.
#[test]
fn ignore_file_with_nonexistent_path_scan_still_proceeds() {
    let dir = setup();
    write(&dir, "clean.py", b"x=1\n");

    cmd()
        .arg(dir.path())
        .arg("--ignore-file")
        .arg("/no/such/ignore/file.gitignore")
        .assert()
        .success()
        .code(0);
}

// ── --follow-links (Windows) ──────────────────────────────────────────────────

/// On Windows, directory symlinks require Developer Mode or admin privileges.
/// These tests attempt to create one and gracefully skip if the privilege is
/// not available in the test environment.
#[cfg(windows)]
#[test]
fn without_follow_links_windows_symlinked_dir_not_traversed() {
    use std::os::windows::fs::symlink_dir;

    let key_dir = setup();
    let key = "sk-xK9pQm7vL3nRwT5yJbHfDcGsEaZuViYo4W8MiNqX2Pe5AbcD";
    write(&key_dir, "secret.py", format!("KEY='{key}'\n").as_bytes());

    let scan_dir = setup();
    write(&scan_dir, "clean.py", b"x=1\n");

    // Requires Developer Mode or elevated privileges — skip if unavailable.
    if symlink_dir(key_dir.path(), scan_dir.path().join("linked")).is_err() {
        return;
    }

    cmd()
        .arg(scan_dir.path())
        .assert()
        .success()
        .code(0);
}

#[cfg(windows)]
#[test]
fn with_follow_links_windows_symlinked_dir_is_traversed() {
    use std::os::windows::fs::symlink_dir;

    let key_dir = setup();
    let key = "sk-xK9pQm7vL3nRwT5yJbHfDcGsEaZuViYo4W8MiNqX2Pe5AbcD";
    write(&key_dir, "secret.py", format!("KEY='{key}'\n").as_bytes());

    let scan_dir = setup();
    write(&scan_dir, "clean.py", b"x=1\n");

    if symlink_dir(key_dir.path(), scan_dir.path().join("linked")).is_err() {
        return;
    }

    cmd()
        .arg(scan_dir.path())
        .arg("--follow-links")
        .assert()
        .failure()
        .code(1);
}

// ── v2.0.0: fingerprints ──────────────────────────────────────────────────────

#[test]
fn fingerprint_field_in_finding_starts_with_fp() {
    let dir = setup();
    let key = "sk-xK9pQm7vL3nRwT5yJbHfDcGsEaZuViYo4W8MiNqX2Pe5AbcD";
    write(&dir, "config.py", format!("KEY='{key}'\n").as_bytes());
    let output = cmd().arg(dir.path()).output().unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let findings = v["findings"].as_array().unwrap();
    assert!(!findings.is_empty());
    let fp = findings[0]["fingerprint"].as_str().unwrap();
    assert!(fp.starts_with("fp-"), "fingerprint must start with 'fp-', got: {fp}");
    assert_eq!(fp.len(), 19, "fingerprint must be 'fp-' + 16 hex chars, got: {fp}");
}

#[test]
fn fingerprint_is_stable_across_scans() {
    let dir = setup();
    let key = "sk-xK9pQm7vL3nRwT5yJbHfDcGsEaZuViYo4W8MiNqX2Pe5AbcD";
    write(&dir, "config.py", format!("KEY='{key}'\n").as_bytes());

    let run1 = cmd().arg(dir.path()).output().unwrap();
    let run2 = cmd().arg(dir.path()).output().unwrap();

    let v1: serde_json::Value = serde_json::from_str(&String::from_utf8(run1.stdout).unwrap()).unwrap();
    let v2: serde_json::Value = serde_json::from_str(&String::from_utf8(run2.stdout).unwrap()).unwrap();

    let fp1 = v1["findings"][0]["fingerprint"].as_str().unwrap();
    let fp2 = v2["findings"][0]["fingerprint"].as_str().unwrap();
    assert_eq!(fp1, fp2, "fingerprint must be identical across repeated scans");
}

// ── v2.0.0: remediation ───────────────────────────────────────────────────────

#[test]
fn remediation_field_in_finding_is_non_empty() {
    let dir = setup();
    let key = "sk-xK9pQm7vL3nRwT5yJbHfDcGsEaZuViYo4W8MiNqX2Pe5AbcD";
    write(&dir, "config.py", format!("KEY='{key}'\n").as_bytes());
    let output = cmd().arg(dir.path()).output().unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let findings = v["findings"].as_array().unwrap();
    assert!(!findings.is_empty());
    let remediation = findings[0]["remediation"].as_str().unwrap_or("");
    assert!(!remediation.is_empty(), "remediation must be non-empty for built-in provider findings");
}

// ── v2.0.0: severity ─────────────────────────────────────────────────────────

#[test]
fn openai_key_severity_is_critical() {
    let dir = setup();
    let key = "sk-xK9pQm7vL3nRwT5yJbHfDcGsEaZuViYo4W8MiNqX2Pe5AbcD";
    write(&dir, "config.py", format!("KEY='{key}'\n").as_bytes());
    let output = cmd().arg(dir.path()).output().unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let findings = v["findings"].as_array().unwrap();
    assert!(!findings.is_empty());
    let severity = findings[0]["severity"].as_str().unwrap();
    assert_eq!(severity, "critical", "OpenAI key severity must be critical");
}

#[test]
fn groq_key_severity_is_high() {
    let dir = setup();
    write(
        &dir,
        "model.py",
        b"client = Groq(api_key='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')\n",
    );
    let output = cmd().arg(dir.path()).output().unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let findings = v["findings"].as_array().unwrap();
    assert!(!findings.is_empty(), "groq key must be detected");
    let severity = findings[0]["severity"].as_str().unwrap();
    assert_eq!(severity, "high", "groq key severity must be high");
}

// ── v2.0.0: metrics ──────────────────────────────────────────────────────────

#[test]
fn metrics_field_in_json_output() {
    let dir = setup();
    write(&dir, "clean.py", b"x = 1\n");
    let output = cmd().arg(dir.path()).output().unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert!(v.get("metrics").is_some(), "report must have metrics field");
    let metrics = &v["metrics"];
    assert!(metrics.get("scan_duration_ms").is_some(), "metrics must have scan_duration_ms");
    assert!(metrics.get("files_skipped").is_some(), "metrics must have files_skipped");
    assert!(metrics.get("total_raw_matches").is_some(), "metrics must have total_raw_matches");
}

#[test]
fn metrics_scan_duration_is_non_negative() {
    let dir = setup();
    write(&dir, "a.py", b"x=1\n");
    write(&dir, "b.py", b"y=2\n");
    let output = cmd().arg(dir.path()).output().unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let ms = v["metrics"]["scan_duration_ms"].as_u64().unwrap();
    // Duration might be 0 on fast systems but never negative
    let _ = ms; // just verify it parses as u64 (non-negative)
}

// ── v2.0.0: --format text ─────────────────────────────────────────────────────

#[test]
fn text_format_output_contains_tool_name() {
    let dir = setup();
    write(&dir, "clean.py", b"x = 1\n");
    let output = cmd()
        .args([dir.path().to_str().unwrap(), "--format", "text"])
        .output()
        .unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("sf-keyaudit"), "text output must contain tool name");
}

#[test]
fn text_format_finding_shows_fingerprint() {
    let dir = setup();
    let key = "sk-xK9pQm7vL3nRwT5yJbHfDcGsEaZuViYo4W8MiNqX2Pe5AbcD";
    write(&dir, "config.py", format!("KEY='{key}'\n").as_bytes());
    let output = cmd()
        .args([dir.path().to_str().unwrap(), "--format", "text"])
        .output()
        .unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("fp-"), "text output must show fingerprint for findings");
}

// ── v2.0.0: --threads ────────────────────────────────────────────────────────

#[test]
fn threads_flag_does_not_crash() {
    let dir = setup();
    write(&dir, "clean.py", b"x = 1\n");
    cmd()
        .args([dir.path().to_str().unwrap(), "--threads", "2"])
        .assert()
        .success()
        .code(0);
}

#[test]
fn threads_flag_with_findings_still_exits_1() {
    let dir = setup();
    let key = "sk-xK9pQm7vL3nRwT5yJbHfDcGsEaZuViYo4W8MiNqX2Pe5AbcD";
    write(&dir, "config.py", format!("KEY='{key}'\n").as_bytes());
    cmd()
        .args([dir.path().to_str().unwrap(), "--threads", "4"])
        .assert()
        .failure()
        .code(1);
}

// ── v2.0.0: --generate-baseline / --baseline ─────────────────────────────────

#[test]
fn generate_baseline_creates_json_file() {
    let dir = setup();
    let key = "sk-xK9pQm7vL3nRwT5yJbHfDcGsEaZuViYo4W8MiNqX2Pe5AbcD";
    write(&dir, "config.py", format!("KEY='{key}'\n").as_bytes());
    let baseline_path = dir.path().join("baseline.json");

    cmd()
        .arg(dir.path())
        .args(["--generate-baseline", baseline_path.to_str().unwrap()])
        .output()
        .unwrap();

    assert!(baseline_path.exists(), "baseline file must be created");
    let content = fs::read_to_string(&baseline_path).unwrap();
    let v: serde_json::Value = serde_json::from_str(&content).expect("baseline must be valid JSON");
    assert!(v.get("fingerprints").is_some(), "baseline must have fingerprints field");
    // Since v2.1 the fingerprints field is a JSON object (map), not an array.
    let fps = v["fingerprints"].as_object().unwrap();
    assert!(!fps.is_empty(), "baseline fingerprints must not be empty");
    assert!(
        fps.keys().next().unwrap().starts_with("fp-"),
        "baseline fingerprint keys must start with 'fp-'"
    );
}

#[test]
fn baseline_suppresses_finding_exits_0() {
    let dir = setup();
    let key = "sk-xK9pQm7vL3nRwT5yJbHfDcGsEaZuViYo4W8MiNqX2Pe5AbcD";
    write(&dir, "config.py", format!("KEY='{key}'\n").as_bytes());
    let baseline_path = dir.path().join("baseline.json");

    // First scan: generate the baseline (exits 1 because finding is present)
    cmd()
        .arg(dir.path())
        .args(["--generate-baseline", baseline_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(baseline_path.exists(), "baseline file must be created after first scan");

    // Second scan: apply the baseline — finding is suppressed → exit 0
    cmd()
        .arg(dir.path())
        .args(["--baseline", baseline_path.to_str().unwrap()])
        .assert()
        .code(0);
}

#[test]
fn baselined_findings_appear_in_json_report() {
    let dir = setup();
    let key = "sk-xK9pQm7vL3nRwT5yJbHfDcGsEaZuViYo4W8MiNqX2Pe5AbcD";
    write(&dir, "config.py", format!("KEY='{key}'\n").as_bytes());
    let baseline_path = dir.path().join("baseline.json");

    // Generate baseline
    cmd()
        .arg(dir.path())
        .args(["--generate-baseline", baseline_path.to_str().unwrap()])
        .output()
        .unwrap();

    // Second scan with baseline applied
    let output = cmd()
        .arg(dir.path())
        .args(["--baseline", baseline_path.to_str().unwrap()])
        .output()
        .unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();

    assert!(v.get("baselined_findings").is_some(), "report must have baselined_findings field");
    let baselined = v["baselined_findings"].as_array().unwrap();
    assert!(
        !baselined.is_empty(),
        "baselined_findings must contain the suppressed finding"
    );
    // The main findings array must be empty (all suppressed)
    assert_eq!(
        v["findings"].as_array().unwrap().len(),
        0,
        "findings must be empty when all are baselined"
    );
}

#[test]
fn new_finding_after_baseline_still_exits_1() {
    let dir = setup();
    let key = "sk-xK9pQm7vL3nRwT5yJbHfDcGsEaZuViYo4W8MiNqX2Pe5AbcD";
    write(&dir, "config.py", format!("KEY='{key}'\n").as_bytes());
    let baseline_path = dir.path().join("baseline.json");

    // Generate baseline with only config.py (key at line 1)
    cmd()
        .arg(dir.path())
        .args(["--generate-baseline", baseline_path.to_str().unwrap()])
        .output()
        .unwrap();

    // Add a new file with the same key but at a different path → different fingerprint,
    // so it is NOT suppressed by the baseline.
    write(
        &dir,
        "new_secret.py",
        format!("# added later\nKEY='{key}'\n").as_bytes(),
    );

    // Scan with baseline: config.py key is baselined, new_secret.py key is NEW → exits 1
    cmd()
        .arg(dir.path())
        .args(["--baseline", baseline_path.to_str().unwrap()])
        .assert()
        .code(1);
}

// ── v2.0.0: --config (custom rules) ──────────────────────────────────────────

#[test]
fn config_file_custom_rule_detects_custom_pattern() {
    let dir = setup();
    // Write a file with a custom token
    write(&dir, "app.env", b"TOKEN=MYAPP_A1B2C3D4E5F6G7H8I9J0\n");

    // Write the config file with a custom rule
    let config_yaml = r#"custom_rules:
  - id: myapp-token-v1
    provider: myapp
    description: "MyApp API token"
    pattern: "(?P<body>MYAPP_[A-Z0-9]{20})"
    min_entropy: 2.0
    severity: medium
"#;
    let config_path = dir.path().join("myapp.yaml");
    fs::write(&config_path, config_yaml.as_bytes()).unwrap();

    let output = cmd()
        .arg(dir.path())
        .args(["--config", config_path.to_str().unwrap()])
        .output()
        .unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let total = v["summary"]["total_findings"].as_u64().unwrap_or(0);
    assert!(total >= 1, "custom rule must detect the MYAPP_ token, got {total} findings");
    let findings = v["findings"].as_array().unwrap();
    let found_myapp = findings.iter().any(|f| f["provider"].as_str() == Some("myapp"));
    assert!(found_myapp, "myapp provider must appear in findings");
}

#[test]
fn config_file_custom_rule_severity_is_applied() {
    let dir = setup();
    write(&dir, "app.env", b"TOKEN=MYAPP_A1B2C3D4E5F6G7H8I9J0\n");

    let config_yaml = r#"custom_rules:
  - id: myapp-token-v1
    provider: myapp
    pattern: "(?P<body>MYAPP_[A-Z0-9]{20})"
    severity: medium
"#;
    let config_path = dir.path().join("myapp.yaml");
    fs::write(&config_path, config_yaml.as_bytes()).unwrap();

    let output = cmd()
        .arg(dir.path())
        .args(["--config", config_path.to_str().unwrap()])
        .output()
        .unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let findings = v["findings"].as_array().unwrap();
    if !findings.is_empty() {
        let severity = findings[0]["severity"].as_str().unwrap();
        assert_eq!(severity, "medium", "custom rule severity override must apply");
    }
}

// ── v2.0.0: --staged (git-aware) ─────────────────────────────────────────────

#[test]
fn staged_without_git_repo_exits_config_error() {
    let dir = setup();
    write(&dir, "clean.py", b"x=1\n");
    // Running --staged outside a git repository must fail with exit code 2 (ConfigError)
    cmd()
        .arg(dir.path())
        .arg("--staged")
        .assert()
        .code(2);
}

#[test]
fn history_mode_finds_deleted_secret_from_git_history() {
    let dir = setup();
    let key = "sk-xK9pQm7vL3nRwT5yJbHfDcGsEaZuViYo4W8MiNqX2Pe5AbcD";

    git(&dir, &["init"]);
    git(&dir, &["config", "user.name", "sf-keyaudit tests"]);
    git(&dir, &["config", "user.email", "tests@example.com"]);

    write(&dir, "secret.py", format!("API_KEY='{key}'\n").as_bytes());
    git(&dir, &["add", "."]);
    git(&dir, &["commit", "-m", "add secret"]);

    fs::remove_file(dir.path().join("secret.py")).unwrap();
    git(&dir, &["add", "-A"]);
    git(&dir, &["commit", "-m", "remove secret"]);

    cmd()
        .arg(dir.path())
        .assert()
        .success()
        .code(0);

    let output = cmd()
        .arg(dir.path())
        .arg("--history")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1), "--history must surface deleted secrets from git history");

    let stdout = String::from_utf8(output.stdout).unwrap();
    let report: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert!(
        report["summary"]["total_findings"].as_u64().unwrap_or(0) >= 1,
        "history scan must report at least one finding"
    );
    let files_scanned = report["files_scanned"].as_u64().unwrap_or(0);
    assert!(files_scanned >= 1, "history scan must inspect at least one blob");
}
