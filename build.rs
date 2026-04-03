use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    // Build number: taken from the CI run counter when available, otherwise 0.
    let build_number = std::env::var("GITHUB_RUN_NUMBER")
        .unwrap_or_else(|_| "0".to_string());
    println!("cargo:rustc-env=SF_BUILD_NUMBER={build_number}");
    println!("cargo:rerun-if-env-changed=GITHUB_RUN_NUMBER");

    // Calendar year at compile time (correct for any year, leap-year-aware).
    println!("cargo:rustc-env=SF_BUILD_YEAR={}", build_year());
}

fn build_year() -> u64 {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut year = 1970u64;
    let mut remaining = secs;
    loop {
        let secs_in_year = if is_leap(year) { 366 * 86_400 } else { 365 * 86_400 };
        if remaining < secs_in_year {
            break;
        }
        remaining -= secs_in_year;
        year += 1;
    }
    year
}

fn is_leap(y: u64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}
