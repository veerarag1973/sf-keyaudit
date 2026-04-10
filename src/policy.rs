//! Policy pack evaluation engine.
//!
//! A *policy* consists of:
//! 1. A **pack** — a named set of thresholds and enforcement defaults
//!    (see [`PolicyPackName`]).
//! 2. **Overrides** in [`PolicyConfig`] that tune the pack for the project.
//!
//! The engine evaluates every [`Finding`] and produces a [`PolicyDecision`]
//! (`Block`, `Warn`, or `Allow`) plus a human-readable justification.
//! The caller (main.rs) aggregates these decisions to determine the process
//! exit code.
//!
//! # Design
//! * Pure functions — no I/O, no global state.
//! * The engine never modifies findings; it only *annotates* decisions.
//! * All built-in pack defaults are defined as constants so they are visible
//!   in code review and documentation.

use crate::config::{PolicyConfig, PolicyPackName};
use crate::types::{Finding, TriageState};
// PolicyDecision and PolicyViolation are defined in crate::types and
// re-exported here for ergonomic use by callers that import from policy.
pub use crate::types::{PolicyDecision, PolicyViolation};

// ── Pack defaults ──────────────────────────────────────────────────────────────

/// Severity levels that cause exit-code 1 under `strict-ci`.
const STRICT_CI_BLOCK: &[&str] = &["critical", "high"];
/// Severity levels that cause exit-code 1 under `developer-friendly`.
const DEV_FRIENDLY_BLOCK: &[&str] = &["critical"];
/// Severity levels that cause exit-code 1 under `enterprise-default`.
const ENTERPRISE_BLOCK: &[&str] = &["critical", "high"];
/// Severity levels that cause exit-code 1 under `regulated-env`.
const REGULATED_BLOCK: &[&str] = &["critical", "high", "medium"];

// ── Built-in pack resolution ───────────────────────────────────────────────────

/// Return the severity levels that trigger `Block` for the given pack.
fn blocking_severities(pack: &PolicyPackName) -> &'static [&'static str] {
    match pack {
        PolicyPackName::StrictCi         => STRICT_CI_BLOCK,
        PolicyPackName::DeveloperFriendly => DEV_FRIENDLY_BLOCK,
        PolicyPackName::EnterpriseDefault => ENTERPRISE_BLOCK,
        PolicyPackName::RegulatedEnv      => REGULATED_BLOCK,
        PolicyPackName::Custom            => &[], // custom pack blocks nothing by default
    }
}

// ── Public API ─────────────────────────────────────────────────────────────────

/// Evaluate a slice of findings against `policy` and return all violations.
///
/// Findings whose [`TriageState`] is `FalsePositive`, `AcceptedRisk`, or
/// `Fixed` are automatically allowed and never blocked.
///
/// The returned list may be empty (all allowed) or contain `Block` and `Warn`
/// entries.
pub fn evaluate(findings: &[Finding], policy: &PolicyConfig) -> Vec<PolicyViolation> {
    findings.iter().filter_map(|f| evaluate_one(f, policy)).collect()
}

/// Evaluate a single finding.  Returns `None` when the finding is fully
/// suppressed / allowed without any annotation needed.
fn evaluate_one(finding: &Finding, policy: &PolicyConfig) -> Option<PolicyViolation> {
    // ── 0. Confidence tier filter ─────────────────────────────────────────
    // If the policy specifies a minimum confidence tier, skip findings that
    // fall below it.  Findings with unknown confidence (None) are evaluated
    // normally — we err on the side of caution.
    if let Some(min_conf) = policy.confidence_min {
        if let Some(tier) = finding.confidence {
            if tier < min_conf {
                return None;
            }
        }
    }

    // ── 1. Check per-pattern rule_overrides first ───────────────────────────
    if let Some(rule) = policy.rule_overrides.get(&finding.pattern_id) {
        let decision = match rule.as_str() {
            "block" => PolicyDecision::Block,
            "warn"  => PolicyDecision::Warn,
            "allow" => return None, // fully suppressed
            other   => {
                tracing::warn!(
                    pattern_id = %finding.pattern_id,
                    rule = %other,
                    "unknown policy rule_override value — treating as 'warn'"
                );
                PolicyDecision::Warn
            }
        };
        return Some(PolicyViolation {
            fingerprint: finding.fingerprint.clone(),
            rule: format!("rule-override:{}", finding.pattern_id),
            decision,
            justification: format!(
                "per-pattern rule override for '{}': {rule}",
                finding.pattern_id
            ),
        });
    }

    // ── 2. Triage suppression ───────────────────────────────────────────────
    if let Some(
        TriageState::FalsePositive | TriageState::AcceptedRisk | TriageState::Fixed,
    ) = finding.triage_state
    {
        return None;
    }

    // ── 3. Check confirmed-live override ───────────────────────────────────
    let is_confirmed_live = finding
        .validation_status
        .as_deref()
        .map(|s| s == "network-confirmed-valid")
        .unwrap_or(false);

    if is_confirmed_live && policy.block_on_confirmed_live {
        return Some(PolicyViolation {
            fingerprint: finding.fingerprint.clone(),
            rule: "confirmed-live-credential".into(),
            decision: PolicyDecision::Block,
            justification: "network validation confirmed this credential is live".into(),
        });
    }

    // ── 4. Severity threshold ───────────────────────────────────────────────
    let effective_min = policy
        .min_severity_to_fail
        .as_deref()
        .unwrap_or_else(|| default_min_severity(&policy.pack));

    let decision = severity_decision(&finding.severity, effective_min, &policy.pack);

    match decision {
        PolicyDecision::Allow => None,
        d => {
            // ── 5. require_owner check ─────────────────────────────────────
            // Only applies for `Block`-level findings.
            if policy.require_owner && d == PolicyDecision::Block && finding.owner.is_none() {
                return Some(PolicyViolation {
                    fingerprint: finding.fingerprint.clone(),
                    rule: format!("require-owner:{}", finding.severity),
                    decision: PolicyDecision::Block,
                    justification: format!(
                        "{} finding has no owner; policy requires owner annotation for blocking-severity findings",
                        finding.severity
                    ),
                });
            }

            Some(PolicyViolation {
                fingerprint: finding.fingerprint.clone(),
                rule: format!("severity:{}:{}", policy.pack, finding.severity),
                decision: d,
                justification: format!(
                    "severity '{}' meets or exceeds block threshold '{}' under '{}' policy pack",
                    finding.severity,
                    effective_min,
                    policy.pack
                ),
            })
        }
    }
}

/// Return the minimum-severity-to-fail string for a pack when no explicit
/// `min_severity_to_fail` override is set.
fn default_min_severity(pack: &PolicyPackName) -> &'static str {
    match pack {
        PolicyPackName::StrictCi         => "high",
        PolicyPackName::DeveloperFriendly => "critical",
        PolicyPackName::EnterpriseDefault => "high",
        PolicyPackName::RegulatedEnv      => "medium",
        PolicyPackName::Custom            => "critical", // safest default
    }
}

/// Map a severity string + threshold to a [`PolicyDecision`].
///
/// Severity ordering: critical > high > medium > low.
fn severity_decision(severity: &str, min_to_fail: &str, pack: &PolicyPackName) -> PolicyDecision {
    let blocking = blocking_severities(pack);
    if blocking.contains(&severity) && severity_gte(severity, min_to_fail) {
        PolicyDecision::Block
    } else if severity_gte(severity, "medium") {
        PolicyDecision::Warn
    } else {
        PolicyDecision::Allow
    }
}

/// Returns `true` when `a` is greater-than-or-equal to `b` in the canonical
/// severity ordering: critical ≥ high ≥ medium ≥ low.
fn severity_gte(a: &str, b: &str) -> bool {
    fn rank(s: &str) -> u8 {
        match s {
            "critical" => 4,
            "high"     => 3,
            "medium"   => 2,
            "low"      => 1,
            _          => 0,
        }
    }
    rank(a) >= rank(b)
}

// ── Summary helpers ────────────────────────────────────────────────────────────

/// Count the number of [`PolicyDecision::Block`] violations in a list.
pub fn block_count(violations: &[PolicyViolation]) -> usize {
    violations.iter().filter(|v| v.decision == PolicyDecision::Block).count()
}

/// Count the number of [`PolicyDecision::Warn`] violations in a list.
pub fn warn_count(violations: &[PolicyViolation]) -> usize {
    violations.iter().filter(|v| v.decision == PolicyDecision::Warn).count()
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{PolicyConfig, PolicyPackName};
    use crate::types::Finding;

    fn finding(severity: &str) -> Finding {
        let mut f = Finding::new(
            1,
            "openai",
            "src/config.py",
            1,
            1,
            "sk-***REDACTED***".to_string(),
            "openai-legacy-key-v1",
            3.9,
        );
        f.severity = severity.to_string();
        f
    }

    #[test]
    fn strict_ci_blocks_high() {
        let policy = PolicyConfig {
            pack: PolicyPackName::StrictCi,
            block_on_confirmed_live: true,
            ..Default::default()
        };
        let f = finding("high");
        let violations = evaluate(&[f], &policy);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].decision, PolicyDecision::Block);
    }

    #[test]
    fn dev_friendly_allows_high() {
        let policy = PolicyConfig {
            pack: PolicyPackName::DeveloperFriendly,
            block_on_confirmed_live: false,
            ..Default::default()
        };
        let f = finding("high");
        let violations = evaluate(&[f], &policy);
        // high is warn-only under developer-friendly
        assert!(violations.iter().all(|v| v.decision != PolicyDecision::Block));
    }

    #[test]
    fn false_positive_always_allowed() {
        let policy = PolicyConfig {
            pack: PolicyPackName::StrictCi,
            block_on_confirmed_live: true,
            ..Default::default()
        };
        let mut f = finding("critical");
        f.triage_state = Some(TriageState::FalsePositive);
        let violations = evaluate(&[f], &policy);
        assert!(violations.is_empty());
    }

    #[test]
    fn rule_override_block() {
        let mut policy = PolicyConfig {
            pack: PolicyPackName::DeveloperFriendly,
            block_on_confirmed_live: false,
            ..Default::default()
        };
        policy.rule_overrides.insert("openai-legacy-key-v1".into(), "block".into());
        let f = finding("high");
        let violations = evaluate(&[f], &policy);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].decision, PolicyDecision::Block);
    }

    #[test]
    fn confirmed_live_blocks() {
        let policy = PolicyConfig {
            pack: PolicyPackName::DeveloperFriendly,
            block_on_confirmed_live: true,
            ..Default::default()
        };
        let mut f = finding("medium");
        f.validation_status = Some("network-confirmed-valid".into());
        let violations = evaluate(&[f], &policy);
        assert!(violations.iter().any(|v| v.decision == PolicyDecision::Block));
    }

    #[test]
    fn enterprise_default_blocks_high() {
        let policy = PolicyConfig {
            pack: PolicyPackName::EnterpriseDefault,
            block_on_confirmed_live: false,
            ..Default::default()
        };
        let f = finding("high");
        let violations = evaluate(&[f], &policy);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].decision, PolicyDecision::Block);
    }

    #[test]
    fn regulated_env_blocks_medium() {
        let policy = PolicyConfig {
            pack: PolicyPackName::RegulatedEnv,
            block_on_confirmed_live: false,
            ..Default::default()
        };
        let f = finding("medium");
        let violations = evaluate(&[f], &policy);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].decision, PolicyDecision::Block);
    }

    #[test]
    fn block_count_sums_correctly() {
        let policy = PolicyConfig {
            pack: PolicyPackName::StrictCi,
            block_on_confirmed_live: false,
            ..Default::default()
        };
        let findings = vec![finding("critical"), finding("high"), finding("medium")];
        let violations = evaluate(&findings, &policy);
        // critical and high block; medium is below strict-ci threshold (which blocks high+critical)
        assert_eq!(block_count(&violations), 2);
    }

    #[test]
    fn warn_count_sums_correctly() {
        let policy = PolicyConfig {
            pack: PolicyPackName::DeveloperFriendly,
            block_on_confirmed_live: false,
            ..Default::default()
        };
        // high is warn-only under developer-friendly
        let violations = evaluate(&[finding("high")], &policy);
        assert_eq!(warn_count(&violations), 1);
        assert_eq!(block_count(&violations), 0);
    }

    #[test]
    fn require_owner_warns_when_owner_missing() {
        let policy = PolicyConfig {
            pack: PolicyPackName::StrictCi,
            block_on_confirmed_live: false,
            require_owner: true,
            ..Default::default()
        };
        // finding("high") under StrictCi would normally block; with require_owner it
        // also blocks but with a different rule label.
        let mut f = finding("high");
        f.owner = None;
        let violations = evaluate(&[f], &policy);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].decision, PolicyDecision::Block);
        assert!(violations[0].rule.contains("require-owner"));
    }

    // ── confidence_min filtering ───────────────────────────────────────────────

    #[test]
    fn confidence_min_high_skips_medium_finding() {
        use crate::patterns::ConfidenceTier;
        let policy = PolicyConfig {
            pack: PolicyPackName::StrictCi,
            block_on_confirmed_live: false,
            confidence_min: Some(ConfidenceTier::High),
            ..Default::default()
        };
        let mut f = finding("critical");
        f.confidence = Some(ConfidenceTier::Medium);
        // Medium < High → finding should be skipped → no violations
        let violations = evaluate(&[f], &policy);
        assert!(violations.is_empty(), "medium-confidence finding must be skipped");
    }

    #[test]
    fn confidence_min_passes_high_finding() {
        use crate::patterns::ConfidenceTier;
        let policy = PolicyConfig {
            pack: PolicyPackName::StrictCi,
            block_on_confirmed_live: false,
            confidence_min: Some(ConfidenceTier::High),
            ..Default::default()
        };
        let mut f = finding("critical");
        f.confidence = Some(ConfidenceTier::High);
        // High >= High → finding must be evaluated
        let violations = evaluate(&[f], &policy);
        assert!(!violations.is_empty(), "high-confidence finding must not be skipped");
    }

    #[test]
    fn confidence_min_none_does_not_filter() {
        // When confidence_min is not set, all findings are evaluated regardless of confidence.
        let policy = PolicyConfig {
            pack: PolicyPackName::StrictCi,
            block_on_confirmed_live: false,
            confidence_min: None,
            ..Default::default()
        };
        // A finding without any confidence annotation must still be evaluated.
        let f = finding("critical"); // confidence is None
        let violations = evaluate(&[f], &policy);
        assert!(!violations.is_empty(), "finding with no confidence must not be filtered");
    }
}
