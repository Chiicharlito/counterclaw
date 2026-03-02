//! Tests for BUG 2 — CDP Proxy: HTTP Redirect Bypass (CRITICAL)
//!
//! Chrome events (Page.frameNavigated, Network.requestWillBeSent) bypass inspection
//! because process_cdp_message forwards all messages without `id`.
//! These tests verify that process_chrome_event() detects navigation
//! to blocked domains in Chrome-initiated events.

mod common;

use counterclaw::config::DomainRulesConfig;
use counterclaw::guards::cdp_proxy::{
    process_chrome_event, CdpSessionState, ChromeEventDecision, DomainMatcher,
};
use counterclaw::types::OperationMode;

fn blocked_domains_matcher() -> DomainMatcher {
    DomainMatcher::new(&DomainRulesConfig {
        blocked: vec!["mail.google.com".to_string(), "gmail.com".to_string()],
        allowed: vec!["github.com".to_string()],
        require_approval: vec!["amazon.com".to_string()],
        default_policy: "allow".to_string(),
    })
}

// ---------------------------------------------------------------------------
// Test 1: Page.frameNavigated to blocked domain → alerts
// ---------------------------------------------------------------------------
#[test]
fn frame_navigated_blocked_domain_alerts() {
    let matcher = blocked_domains_matcher();
    let mut session = CdpSessionState::new();
    let mode = OperationMode::Enforce;

    let event_json = r#"{"method":"Page.frameNavigated","params":{"frame":{"url":"https://mail.google.com/mail/u/0/"}}}"#;
    let parsed: serde_json::Value = serde_json::from_str(event_json).unwrap();

    let decision = process_chrome_event(&parsed, &matcher, &mut session, &mode);
    assert!(
        matches!(decision, ChromeEventDecision::Alert { .. }),
        "Page.frameNavigated to blocked domain should produce Alert, got: {:?}",
        decision
    );
}

// ---------------------------------------------------------------------------
// Test 2: Page.frameNavigated to allowed domain → updates session
// ---------------------------------------------------------------------------
#[test]
fn frame_navigated_allowed_domain_updates_session() {
    let matcher = blocked_domains_matcher();
    let mut session = CdpSessionState::new();
    let mode = OperationMode::Enforce;

    let event_json =
        r#"{"method":"Page.frameNavigated","params":{"frame":{"url":"https://github.com/repo"}}}"#;
    let parsed: serde_json::Value = serde_json::from_str(event_json).unwrap();

    let decision = process_chrome_event(&parsed, &matcher, &mut session, &mode);
    assert!(
        matches!(decision, ChromeEventDecision::Forward),
        "Allowed domain should Forward, got: {:?}",
        decision
    );

    // Session should be updated
    let current = session.current_url();
    assert!(current.is_some(), "Session URL should be updated");
    assert!(
        current.unwrap().contains("github.com"),
        "Session URL should contain github.com"
    );
}

// ---------------------------------------------------------------------------
// Test 3: Page.navigatedWithinDocument to blocked domain → alerts
// ---------------------------------------------------------------------------
#[test]
fn navigated_within_document_blocked_alerts() {
    let matcher = blocked_domains_matcher();
    let mut session = CdpSessionState::new();
    let mode = OperationMode::Enforce;

    let event_json =
        r#"{"method":"Page.navigatedWithinDocument","params":{"url":"https://gmail.com/inbox"}}"#;
    let parsed: serde_json::Value = serde_json::from_str(event_json).unwrap();

    let decision = process_chrome_event(&parsed, &matcher, &mut session, &mode);
    assert!(
        matches!(decision, ChromeEventDecision::Alert { .. }),
        "SPA navigation to blocked domain should Alert, got: {:?}",
        decision
    );
}

// ---------------------------------------------------------------------------
// Test 4: After redirect, session reflects the new (blocked) domain
// ---------------------------------------------------------------------------
#[test]
fn redirect_chain_detected_via_session() {
    let matcher = blocked_domains_matcher();
    let mut session = CdpSessionState::new();
    let mode = OperationMode::Enforce;

    // First: navigate to an allowed domain
    let event1 =
        r#"{"method":"Page.frameNavigated","params":{"frame":{"url":"https://github.com"}}}"#;
    let parsed1: serde_json::Value = serde_json::from_str(event1).unwrap();
    let _ = process_chrome_event(&parsed1, &matcher, &mut session, &mode);
    assert_eq!(session.current_domain(), Some("github.com".to_string()));

    // Then: redirect to blocked domain
    let event2 = r#"{"method":"Page.frameNavigated","params":{"frame":{"url":"https://mail.google.com/mail"}}}"#;
    let parsed2: serde_json::Value = serde_json::from_str(event2).unwrap();
    let decision = process_chrome_event(&parsed2, &matcher, &mut session, &mode);

    assert!(
        matches!(decision, ChromeEventDecision::Alert { .. }),
        "Redirect to blocked domain should Alert"
    );

    // Session should still reflect the blocked domain was detected
    // (in enforce mode, we update session so restricted commands on this domain are blocked)
    assert_eq!(
        session.current_domain(),
        Some("mail.google.com".to_string()),
        "Session should track the blocked domain for subsequent command filtering"
    );
}

// ---------------------------------------------------------------------------
// Test 5: Events without method → Forward
// ---------------------------------------------------------------------------
#[test]
fn events_without_method_forward() {
    let matcher = blocked_domains_matcher();
    let mut session = CdpSessionState::new();
    let mode = OperationMode::Monitor;

    // JSON with no "method" field
    let event_json = r#"{"id":1,"result":{}}"#;
    let parsed: serde_json::Value = serde_json::from_str(event_json).unwrap();

    let decision = process_chrome_event(&parsed, &matcher, &mut session, &mode);
    assert!(
        matches!(decision, ChromeEventDecision::Forward),
        "Message without method should Forward, got: {:?}",
        decision
    );
}

// ---------------------------------------------------------------------------
// Test 6: Normal Chrome events pass through
// ---------------------------------------------------------------------------
#[test]
fn normal_chrome_events_pass_through() {
    let matcher = blocked_domains_matcher();
    let mut session = CdpSessionState::new();
    let mode = OperationMode::Enforce;

    // DOM.documentUpdated is a normal event that should pass through
    let event_json = r#"{"method":"DOM.documentUpdated"}"#;
    let parsed: serde_json::Value = serde_json::from_str(event_json).unwrap();

    let decision = process_chrome_event(&parsed, &matcher, &mut session, &mode);
    assert!(
        matches!(decision, ChromeEventDecision::Forward),
        "Normal Chrome event should Forward, got: {:?}",
        decision
    );
}

// ---------------------------------------------------------------------------
// Test 7: Blocked redirect in enforce mode → Critical severity
// ---------------------------------------------------------------------------
#[test]
fn blocked_redirect_enforce_higher_severity() {
    let matcher = blocked_domains_matcher();
    let mut session = CdpSessionState::new();
    let mode = OperationMode::Enforce;

    let event_json = r#"{"method":"Page.frameNavigated","params":{"frame":{"url":"https://mail.google.com/mail"}}}"#;
    let parsed: serde_json::Value = serde_json::from_str(event_json).unwrap();

    let decision = process_chrome_event(&parsed, &matcher, &mut session, &mode);
    if let ChromeEventDecision::Alert { severity, .. } = decision {
        assert_eq!(
            severity,
            counterclaw::types::Severity::Critical,
            "Enforce mode should use Critical severity"
        );
    } else {
        panic!("Expected Alert, got: {:?}", decision);
    }
}
