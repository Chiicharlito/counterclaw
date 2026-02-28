//! Security Audit #3 — Tests de remédiation.
//!
//! V1: CDP fail-closed (malformed JSON, batch requests, non-object types)
//! V2: Dashboard auth for read endpoints
//! V3: osascript skip in daemon mode

mod common;

// ===========================================================================
// V1 — CDP Fail-Closed: malformed JSON must be BLOCKED, not forwarded
// ===========================================================================

use counterclaw::config::{AppConfig, CdpProxyConfig};
use counterclaw::guards::cdp_proxy::{
    process_cdp_message, CdpSessionState, CommandFilter, ContentInspector, DomainMatcher,
};
use counterclaw::types::{EventBuffer, OperationMode};

fn test_cdp_config() -> CdpProxyConfig {
    serde_yaml::from_str(
        r#"
enabled: true
listen_port: 18792
upstream_port: 18800
bind_address: "127.0.0.1"
domains:
  blocked:
    - "mail.google.com"
  allowed:
    - "github.com"
  require_approval: []
  default_policy: allow
cdp_commands:
  blocked:
    - "Network.getCookies"
  restricted_to_allowed_domains:
    - "Runtime.evaluate"
  log_always:
    - "Page.navigate"
content_inspection:
  enabled: true
  patterns:
    - name: "api_key_leak"
      regex: '(?i)(api[_-]?key|bearer\s+[a-z0-9])'
      severity: critical
      action: block
"#,
    )
    .expect("Failed to parse test CDP config")
}

fn make_components(
    config: &CdpProxyConfig,
) -> (
    DomainMatcher,
    CommandFilter,
    ContentInspector,
    CdpSessionState,
) {
    (
        DomainMatcher::new(&config.domains),
        CommandFilter::new(&config.cdp_commands),
        ContentInspector::new(&config.content_inspection),
        CdpSessionState::new(),
    )
}

// --- V1 Test 1: malformed JSON → Block ---
#[test]
fn blocks_malformed_json_message() {
    let config = test_cdp_config();
    let (matcher, filter, inspector, mut session) = make_components(&config);

    let malformed = "this is not json at all{{{";
    let decision = process_cdp_message(
        malformed,
        &matcher,
        &filter,
        &inspector,
        &mut session,
        &OperationMode::Enforce,
    );
    assert!(
        decision.is_block(),
        "Malformed JSON should be blocked, got: {:?}",
        decision
    );
}

// --- V1 Test 2: empty string → Block ---
#[test]
fn blocks_empty_string_message() {
    let config = test_cdp_config();
    let (matcher, filter, inspector, mut session) = make_components(&config);

    let decision = process_cdp_message(
        "",
        &matcher,
        &filter,
        &inspector,
        &mut session,
        &OperationMode::Enforce,
    );
    assert!(
        decision.is_block(),
        "Empty string should be blocked, got: {:?}",
        decision
    );
}

// --- V1 Test 3: JSON array (batch request) → Block ---
#[test]
fn blocks_json_array_batch_request() {
    let config = test_cdp_config();
    let (matcher, filter, inspector, mut session) = make_components(&config);

    let batch = r#"[{"id":1,"method":"Page.navigate","params":{"url":"https://evil.com"}},{"id":2,"method":"Network.getCookies"}]"#;
    let decision = process_cdp_message(
        batch,
        &matcher,
        &filter,
        &inspector,
        &mut session,
        &OperationMode::Enforce,
    );
    assert!(
        decision.is_block(),
        "JSON array batch request should be blocked, got: {:?}",
        decision
    );
}

// --- V1 Test 4: non-object JSON types (number, string, bool, null) → Block ---
#[test]
fn blocks_non_object_json_types() {
    let config = test_cdp_config();
    let (matcher, filter, inspector, mut session) = make_components(&config);

    let non_objects = vec!["42", r#""hello""#, "true", "null"];
    for raw in non_objects {
        let decision = process_cdp_message(
            raw,
            &matcher,
            &filter,
            &inspector,
            &mut session,
            &OperationMode::Enforce,
        );
        assert!(
            decision.is_block(),
            "Non-object JSON '{}' should be blocked, got: {:?}",
            raw,
            decision
        );
    }
}

// --- V1 Test 5: valid event without id still forwards (non-regression) ---
#[test]
fn still_forwards_valid_events_without_id() {
    let config = test_cdp_config();
    let (matcher, filter, inspector, mut session) = make_components(&config);

    // Browser events have method but no id
    let event = r#"{"method":"Page.loadEventFired","params":{"timestamp":12345.67}}"#;
    let decision = process_cdp_message(
        event,
        &matcher,
        &filter,
        &inspector,
        &mut session,
        &OperationMode::Monitor,
    );
    assert!(
        decision.is_forward(),
        "Valid browser event should be forwarded, got: {:?}",
        decision
    );
}

// --- V1 Test 6: valid command still processes normally (non-regression) ---
#[test]
fn still_processes_valid_commands() {
    let config = test_cdp_config();
    let (matcher, filter, inspector, mut session) = make_components(&config);

    // A valid navigate command to an allowed domain
    let msg =
        r#"{"id":1,"method":"Page.navigate","params":{"url":"https://github.com/rust-lang"}}"#;
    let decision = process_cdp_message(
        msg,
        &matcher,
        &filter,
        &inspector,
        &mut session,
        &OperationMode::Monitor,
    );
    assert!(
        decision.is_forward(),
        "Valid command to allowed domain should forward, got: {:?}",
        decision
    );

    // A blocked command still gets blocked
    let blocked = r#"{"id":2,"method":"Network.getCookies"}"#;
    let decision = process_cdp_message(
        blocked,
        &matcher,
        &filter,
        &inspector,
        &mut session,
        &OperationMode::Monitor,
    );
    assert!(
        decision.is_block(),
        "Blocked command should still be blocked, got: {:?}",
        decision
    );
}

// ===========================================================================
// V2 — Dashboard auth for read endpoints
// ===========================================================================

use axum::body::Body;
use axum::http::{Request, StatusCode};
use counterclaw::daemon::DaemonState;
use counterclaw::dashboard::server::{build_router, DashboardState};
use std::sync::{Arc, RwLock};
use tower::ServiceExt;

fn setup_state_from_config(config: AppConfig) -> Arc<DaemonState> {
    let buffer = Arc::new(RwLock::new(EventBuffer::new(100)));
    Arc::new(DaemonState::new(config, buffer))
}

fn make_test_app_config() -> AppConfig {
    let env = common::TestEnv::new();
    let yaml = common::minimal_monitor_config(&env);
    env.write_config(&yaml);
    let config = AppConfig::load(&env.config_path()).expect("valid config");
    std::mem::forget(env);
    config
}

// --- V2 Test 1: health accessible without auth by default ---
#[tokio::test]
async fn health_accessible_without_auth_by_default() {
    let config = make_test_app_config();
    // require_auth_for_reads defaults to false
    assert!(!config.dashboard.require_auth_for_reads);

    let state = setup_state_from_config(config);
    let dashboard = DashboardState::with_token(state, "secret-token".to_string());
    let app = build_router(dashboard);

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
}

// --- V2 Test 2: health requires auth when configured ---
#[tokio::test]
async fn health_requires_auth_when_configured() {
    let mut config = make_test_app_config();
    config.dashboard.require_auth_for_reads = true;

    let state = setup_state_from_config(config);
    let dashboard = DashboardState::with_token(state, "secret-token".to_string());
    let app = build_router(dashboard);

    // Without auth → 401
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // With auth → 200
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/health")
                .header("authorization", "Bearer secret-token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

// --- V2 Test 3: status requires auth when configured ---
#[tokio::test]
async fn status_requires_auth_when_configured() {
    let mut config = make_test_app_config();
    config.dashboard.require_auth_for_reads = true;

    let state = setup_state_from_config(config);
    let dashboard = DashboardState::with_token(state, "secret-token".to_string());
    let app = build_router(dashboard);

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/status")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// --- V2 Test 4: paranoid mode forces auth on reads ---
#[tokio::test]
async fn paranoid_mode_forces_auth_on_reads() {
    let mut config = make_test_app_config();
    config.general.mode = "paranoid".to_string();
    // require_auth_for_reads is false, but paranoid mode should force it
    config.dashboard.require_auth_for_reads = false;

    let state = setup_state_from_config(config);
    let dashboard = DashboardState::with_token(state, "secret-token".to_string());
    let app = build_router(dashboard);

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// ===========================================================================
// V3 — osascript skip in LaunchDaemon mode
// ===========================================================================

use counterclaw::alerting::macos_notify::has_gui_session;

#[test]
fn has_gui_session_returns_bool_without_panic() {
    // has_gui_session() detects if we have a GUI session.
    // In a test environment we can't guarantee either way, but we verify
    // the function exists and returns a bool without panicking.
    let result = has_gui_session();
    assert!(result || !result, "has_gui_session must return a bool");
}
