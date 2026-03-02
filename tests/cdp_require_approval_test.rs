//! Tests for BUG 6 — CDP Proxy: require_approval = Allow (MEDIUM)
//!
//! DomainVerdict::RequireApproval returns ForwardAndLog (= allow).
//! Should be mode-dependent: Monitor=ForwardAndLog, Enforce/Paranoid=Block.

mod common;

use counterclaw::config::{CdpCommandsConfig, ContentInspectionConfig, DomainRulesConfig};
use counterclaw::guards::cdp_proxy::{
    process_cdp_message, CdpDecision, CdpSessionState, CommandFilter, ContentInspector,
    DomainMatcher,
};
use counterclaw::types::OperationMode;

fn make_components() -> (DomainMatcher, CommandFilter, ContentInspector) {
    let dm = DomainMatcher::new(&DomainRulesConfig {
        blocked: vec!["mail.google.com".to_string()],
        allowed: vec!["github.com".to_string()],
        require_approval: vec!["amazon.com".to_string()],
        default_policy: "allow".to_string(),
    });
    let cf = CommandFilter::new(&CdpCommandsConfig {
        blocked: vec![],
        restricted_to_allowed_domains: vec![],
        log_always: vec![],
    });
    let ci = ContentInspector::new(&ContentInspectionConfig {
        enabled: false,
        patterns: vec![],
    });
    (dm, cf, ci)
}

// ---------------------------------------------------------------------------
// Test 1: require_approval blocks in enforce mode
// ---------------------------------------------------------------------------
#[test]
fn require_approval_blocks_enforce() {
    let (dm, cf, ci) = make_components();
    let mut session = CdpSessionState::new();
    let mode = OperationMode::Enforce;

    let msg = r#"{"id":1,"method":"Page.navigate","params":{"url":"https://amazon.com/shop"}}"#;
    let decision = process_cdp_message(msg, &dm, &cf, &ci, &mut session, &mode);

    assert!(
        matches!(decision, CdpDecision::Block { .. }),
        "require_approval in Enforce mode should Block, got: {:?}",
        decision
    );
}

// ---------------------------------------------------------------------------
// Test 2: require_approval allows in monitor mode
// ---------------------------------------------------------------------------
#[test]
fn require_approval_allows_monitor() {
    let (dm, cf, ci) = make_components();
    let mut session = CdpSessionState::new();
    let mode = OperationMode::Monitor;

    let msg = r#"{"id":1,"method":"Page.navigate","params":{"url":"https://amazon.com/shop"}}"#;
    let decision = process_cdp_message(msg, &dm, &cf, &ci, &mut session, &mode);

    assert!(
        matches!(decision, CdpDecision::ForwardAndLog { .. }),
        "require_approval in Monitor mode should ForwardAndLog, got: {:?}",
        decision
    );
}

// ---------------------------------------------------------------------------
// Test 3: require_approval blocks in paranoid mode
// ---------------------------------------------------------------------------
#[test]
fn require_approval_blocks_paranoid() {
    let (dm, cf, ci) = make_components();
    let mut session = CdpSessionState::new();
    let mode = OperationMode::Paranoid;

    let msg = r#"{"id":1,"method":"Page.navigate","params":{"url":"https://amazon.com/shop"}}"#;
    let decision = process_cdp_message(msg, &dm, &cf, &ci, &mut session, &mode);

    assert!(
        matches!(decision, CdpDecision::Block { .. }),
        "require_approval in Paranoid mode should Block, got: {:?}",
        decision
    );
}

// ---------------------------------------------------------------------------
// Test 4: require_approval correct severity (Warning)
// ---------------------------------------------------------------------------
#[test]
fn require_approval_correct_severity() {
    let (dm, cf, ci) = make_components();
    let mut session = CdpSessionState::new();
    let mode = OperationMode::Enforce;

    let msg = r#"{"id":1,"method":"Page.navigate","params":{"url":"https://amazon.com/shop"}}"#;
    let decision = process_cdp_message(msg, &dm, &cf, &ci, &mut session, &mode);

    if let CdpDecision::Block { severity, .. } = decision {
        assert_eq!(
            severity,
            counterclaw::types::Severity::Warning,
            "require_approval block should use Warning severity"
        );
    } else {
        panic!("Expected Block, got: {:?}", decision);
    }
}
