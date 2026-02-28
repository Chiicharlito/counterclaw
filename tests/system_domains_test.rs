//! Tests pour les domaines système toujours autorisés (Étape 5).
//!
//! En mode paranoid, certains domaines système (localhost, 127.0.0.1, ::1)
//! doivent TOUJOURS être autorisés pour ne pas casser le fonctionnement de base.

mod common;

use counterclaw::config::DomainRulesConfig;
use counterclaw::guards::cdp_proxy::{DomainMatcher, DomainVerdict, SYSTEM_ALLOWED_DOMAINS};
use counterclaw::types::OperationMode;

// ===========================================================================
// 1. Domaines système toujours autorisés en paranoid
// ===========================================================================

#[test]
fn system_domain_localhost_allowed_in_paranoid() {
    let config = DomainRulesConfig {
        blocked: vec![],
        allowed: vec![],
        require_approval: vec![],
        default_policy: "block".to_string(),
    };
    let matcher = DomainMatcher::new(&config);
    let verdict = matcher.check("localhost", &OperationMode::Paranoid);
    assert_eq!(
        verdict,
        DomainVerdict::Allowed,
        "localhost must always be allowed"
    );
}

#[test]
fn system_domain_127_allowed_in_paranoid() {
    let config = DomainRulesConfig {
        blocked: vec![],
        allowed: vec![],
        require_approval: vec![],
        default_policy: "block".to_string(),
    };
    let matcher = DomainMatcher::new(&config);
    let verdict = matcher.check("127.0.0.1", &OperationMode::Paranoid);
    assert_eq!(
        verdict,
        DomainVerdict::Allowed,
        "127.0.0.1 must always be allowed"
    );
}

#[test]
fn system_domain_ipv6_loopback_allowed_in_paranoid() {
    let config = DomainRulesConfig {
        blocked: vec![],
        allowed: vec![],
        require_approval: vec![],
        default_policy: "block".to_string(),
    };
    let matcher = DomainMatcher::new(&config);
    let verdict = matcher.check("::1", &OperationMode::Paranoid);
    assert_eq!(
        verdict,
        DomainVerdict::Allowed,
        "::1 must always be allowed"
    );
}

// ===========================================================================
// 2. Les domaines système NE PEUVENT PAS être bloqués par la config
// ===========================================================================

#[test]
fn system_domain_cannot_be_blocked_by_config() {
    // Même si la config bloque explicitement localhost, il passe quand même
    let config = DomainRulesConfig {
        blocked: vec!["localhost".to_string(), "127.0.0.1".to_string()],
        allowed: vec![],
        require_approval: vec![],
        default_policy: "block".to_string(),
    };
    let matcher = DomainMatcher::new(&config);

    assert_eq!(
        matcher.check("localhost", &OperationMode::Paranoid),
        DomainVerdict::Allowed,
        "localhost cannot be blocked even if in blocked list"
    );
    assert_eq!(
        matcher.check("127.0.0.1", &OperationMode::Enforce),
        DomainVerdict::Allowed,
        "127.0.0.1 cannot be blocked even if in blocked list"
    );
}

// ===========================================================================
// 3. Un domaine non-système reste bloqué en paranoid
// ===========================================================================

#[test]
fn non_system_domain_blocked_in_paranoid() {
    let config = DomainRulesConfig {
        blocked: vec![],
        allowed: vec![],
        require_approval: vec![],
        default_policy: "allow".to_string(),
    };
    let matcher = DomainMatcher::new(&config);
    let verdict = matcher.check("random-evil.com", &OperationMode::Paranoid);
    assert_eq!(
        verdict,
        DomainVerdict::Blocked,
        "Non-system domain must be blocked in paranoid mode"
    );
}

// ===========================================================================
// 4. Les domaines système sont autorisés dans TOUS les modes
// ===========================================================================

#[test]
fn system_domains_allowed_in_all_modes() {
    let config = DomainRulesConfig {
        blocked: vec!["localhost".to_string()], // essaie de bloquer
        allowed: vec![],
        require_approval: vec![],
        default_policy: "block".to_string(),
    };
    let matcher = DomainMatcher::new(&config);

    for mode in &[
        OperationMode::Monitor,
        OperationMode::Enforce,
        OperationMode::Paranoid,
    ] {
        assert_eq!(
            matcher.check("localhost", mode),
            DomainVerdict::Allowed,
            "localhost must be allowed in {:?} mode",
            mode
        );
    }
}

// ===========================================================================
// 5. La constante SYSTEM_ALLOWED_DOMAINS contient les bons domaines
// ===========================================================================

#[test]
fn system_allowed_domains_contains_expected() {
    assert!(
        SYSTEM_ALLOWED_DOMAINS.contains(&"localhost"),
        "Should contain localhost"
    );
    assert!(
        SYSTEM_ALLOWED_DOMAINS.contains(&"127.0.0.1"),
        "Should contain 127.0.0.1"
    );
    assert!(
        SYSTEM_ALLOWED_DOMAINS.contains(&"::1"),
        "Should contain ::1"
    );
}

// ===========================================================================
// 6. Case insensitive pour les domaines système
// ===========================================================================

#[test]
fn system_domain_case_insensitive() {
    let config = DomainRulesConfig {
        blocked: vec![],
        allowed: vec![],
        require_approval: vec![],
        default_policy: "block".to_string(),
    };
    let matcher = DomainMatcher::new(&config);

    assert_eq!(
        matcher.check("LOCALHOST", &OperationMode::Paranoid),
        DomainVerdict::Allowed,
        "LOCALHOST (uppercase) must be allowed"
    );
    assert_eq!(
        matcher.check("Localhost", &OperationMode::Paranoid),
        DomainVerdict::Allowed,
        "Localhost (mixed case) must be allowed"
    );
}
