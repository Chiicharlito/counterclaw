//! Tests pour le comportement mode-aware des matchers.
//!
//! Vérifie que le cas Unmatched est traité différemment selon le mode :
//! - Monitor : autorisé (log)
//! - Enforce : autorisé
//! - Paranoid : BLOQUÉ (default:deny)

mod common;

use counterclaw::config::CmdGuardConfig;
use counterclaw::guards::cdp_proxy::DomainMatcher;
use counterclaw::guards::cmd_guard::CommandMatcher;
use counterclaw::guards::fs_guard::{PathMatcher, PathVerdict};
use counterclaw::guards::net_guard::{EgressMatcher, EgressVerdict};
use counterclaw::types::OperationMode;
use std::path::Path;

// =========================================================================
// PathMatcher — mode-aware tests
// =========================================================================

#[test]
fn test_fs_guard_unmatched_monitor_allows() {
    let matcher = PathMatcher::new(vec!["~/.ssh".to_string()], vec![], vec![]);
    // Un chemin non-matché en mode monitor → Unmatched (pas bloqué)
    let verdict = matcher.check(Path::new("/tmp/random/file.txt"), &OperationMode::Monitor);
    assert_eq!(verdict, PathVerdict::Unmatched);
}

#[test]
fn test_fs_guard_unmatched_enforce_allows() {
    let matcher = PathMatcher::new(vec!["~/.ssh".to_string()], vec![], vec![]);
    // Un chemin non-matché en mode enforce → Unmatched (pas bloqué)
    let verdict = matcher.check(Path::new("/tmp/random/file.txt"), &OperationMode::Enforce);
    assert_eq!(verdict, PathVerdict::Unmatched);
}

#[test]
fn test_fs_guard_unmatched_paranoid_blocks() {
    let matcher = PathMatcher::new(
        vec!["~/.ssh".to_string()],
        vec![],
        vec!["~/Documents".to_string()],
    );
    // Un chemin non-matché en mode paranoid → Blocked (default:deny)
    let verdict = matcher.check(Path::new("/tmp/random/file.txt"), &OperationMode::Paranoid);
    assert_eq!(verdict, PathVerdict::Blocked);
}

#[test]
fn test_fs_guard_explicit_blocked_in_all_modes() {
    let matcher = PathMatcher::new(vec!["~/.ssh".to_string()], vec![], vec![]);
    let home = dirs::home_dir().unwrap();
    let ssh_path = home.join(".ssh/id_rsa");

    // Blocked est blocked quel que soit le mode
    assert_eq!(
        matcher.check(&ssh_path, &OperationMode::Monitor),
        PathVerdict::Blocked
    );
    assert_eq!(
        matcher.check(&ssh_path, &OperationMode::Enforce),
        PathVerdict::Blocked
    );
    assert_eq!(
        matcher.check(&ssh_path, &OperationMode::Paranoid),
        PathVerdict::Blocked
    );
}

// =========================================================================
// DomainMatcher — mode-aware tests
// =========================================================================

#[test]
fn test_domain_unmatched_monitor_allows() {
    let config = counterclaw::config::DomainRulesConfig {
        blocked: vec!["evil.com".to_string()],
        allowed: vec!["safe.com".to_string()],
        require_approval: vec![],
        default_policy: "allow".to_string(),
    };
    let matcher = DomainMatcher::new(&config);
    // random.org n'est ni bloqué ni autorisé, en monitor → Allowed (permissif)
    let verdict = matcher.check("random.org", &OperationMode::Monitor);
    assert_eq!(
        verdict,
        counterclaw::guards::cdp_proxy::DomainVerdict::Allowed
    );
}

#[test]
fn test_domain_unmatched_enforce_allows() {
    let config = counterclaw::config::DomainRulesConfig {
        blocked: vec!["evil.com".to_string()],
        allowed: vec!["safe.com".to_string()],
        require_approval: vec![],
        default_policy: "allow".to_string(),
    };
    let matcher = DomainMatcher::new(&config);
    let verdict = matcher.check("random.org", &OperationMode::Enforce);
    assert_eq!(
        verdict,
        counterclaw::guards::cdp_proxy::DomainVerdict::Allowed
    );
}

#[test]
fn test_domain_unmatched_paranoid_blocks() {
    let config = counterclaw::config::DomainRulesConfig {
        blocked: vec!["evil.com".to_string()],
        allowed: vec!["safe.com".to_string()],
        require_approval: vec![],
        default_policy: "allow".to_string(),
    };
    let matcher = DomainMatcher::new(&config);
    // En paranoid, un domaine non-matché → Blocked (default:deny) même si default_policy=allow
    let verdict = matcher.check("random.org", &OperationMode::Paranoid);
    assert_eq!(
        verdict,
        counterclaw::guards::cdp_proxy::DomainVerdict::Blocked
    );
}

// =========================================================================
// EgressMatcher — mode-aware tests
// =========================================================================

#[test]
fn test_egress_unmatched_monitor_allows() {
    let matcher = EgressMatcher::new(&["api.github.com".to_string()]);
    // Note: EgressMatcher est déjà default:deny — en monitor on veut Allow pour un domaine inconnu
    let verdict = matcher.check("unknown.com", &OperationMode::Monitor);
    assert_eq!(verdict, EgressVerdict::Allowed);
}

#[test]
fn test_egress_unmatched_enforce_allows() {
    let matcher = EgressMatcher::new(&["api.github.com".to_string()]);
    let verdict = matcher.check("unknown.com", &OperationMode::Enforce);
    assert_eq!(verdict, EgressVerdict::Allowed);
}

#[test]
fn test_egress_unmatched_paranoid_blocks() {
    let matcher = EgressMatcher::new(&["api.github.com".to_string()]);
    // En paranoid, un domaine non dans allowed → Blocked
    let verdict = matcher.check("unknown.com", &OperationMode::Paranoid);
    assert_eq!(verdict, EgressVerdict::Blocked);
}

// =========================================================================
// CommandMatcher — mode-aware tests
// =========================================================================

#[test]
fn test_cmd_unmatched_monitor_allows() {
    let config = CmdGuardConfig {
        enabled: true,
        blacklist: vec![counterclaw::config::CommandPatternConfig {
            pattern: r"rm\s+-rf\s+/".to_string(),
            description: "Dangerous rm".to_string(),
            severity: "critical".to_string(),
        }],
        require_approval: vec![],
        monitoring_method: "log_only".to_string(),
    };
    let matcher = CommandMatcher::new(&config);
    // Une commande non-matchée en monitor → None (pas de verdict = autorisé)
    let verdict = matcher.match_command("ls -la", &OperationMode::Monitor);
    assert!(verdict.is_none());
}

#[test]
fn test_cmd_unmatched_enforce_allows() {
    let config = CmdGuardConfig {
        enabled: true,
        blacklist: vec![counterclaw::config::CommandPatternConfig {
            pattern: r"rm\s+-rf\s+/".to_string(),
            description: "Dangerous rm".to_string(),
            severity: "critical".to_string(),
        }],
        require_approval: vec![],
        monitoring_method: "log_only".to_string(),
    };
    let matcher = CommandMatcher::new(&config);
    let verdict = matcher.match_command("ls -la", &OperationMode::Enforce);
    assert!(verdict.is_none());
}

#[test]
fn test_cmd_unmatched_paranoid_blocks() {
    let config = CmdGuardConfig {
        enabled: true,
        blacklist: vec![counterclaw::config::CommandPatternConfig {
            pattern: r"rm\s+-rf\s+/".to_string(),
            description: "Dangerous rm".to_string(),
            severity: "critical".to_string(),
        }],
        require_approval: vec![],
        monitoring_method: "log_only".to_string(),
    };
    let matcher = CommandMatcher::new(&config);
    // En paranoid, une commande non-matchée → Some(verdict) avec Blocked
    let verdict = matcher.match_command("ls -la", &OperationMode::Paranoid);
    assert!(verdict.is_some());
    let v = verdict.unwrap();
    assert_eq!(
        v.match_type,
        counterclaw::guards::cmd_guard::MatchType::Blacklisted
    );
}
