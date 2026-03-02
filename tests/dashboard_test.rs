//! Tests du dashboard HTTP — endpoints JSON via tower::ServiceExt::oneshot.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use counterclaw::config::AppConfig;
use counterclaw::daemon::DaemonState;
use counterclaw::dashboard::server::{build_router, parse_duration, DashboardState};
use counterclaw::types::{ActionTaken, EventBuffer, GuardModule, SecurityEvent, Severity};
use std::sync::{Arc, RwLock};
use tower::ServiceExt;

fn setup_state() -> Arc<DaemonState> {
    let env = common::TestEnv::new();
    let yaml = common::minimal_monitor_config(&env);
    env.write_config(&yaml);
    let config = AppConfig::load(&env.config_path()).expect("valid config");
    let buffer = Arc::new(RwLock::new(EventBuffer::new(100)));
    // Leak the TestEnv so temp dir stays alive for the duration of the test
    std::mem::forget(env);
    Arc::new(DaemonState::new(config, buffer))
}

fn setup_state_with_events() -> Arc<DaemonState> {
    let env = common::TestEnv::new();
    let yaml = common::minimal_monitor_config(&env);
    env.write_config(&yaml);
    let config = AppConfig::load(&env.config_path()).expect("valid config");
    let buffer = Arc::new(RwLock::new(EventBuffer::new(100)));

    // Pre-populate buffer with events
    {
        let mut buf = buffer.write().unwrap();
        buf.push(SecurityEvent::new(
            GuardModule::FsGuard,
            Severity::Warning,
            ActionTaken::Blocked,
            "File access blocked".to_string(),
        ));
        buf.push(SecurityEvent::new(
            GuardModule::CdpProxy,
            Severity::Critical,
            ActionTaken::Blocked,
            "Domain blocked".to_string(),
        ));
        buf.push(SecurityEvent::new(
            GuardModule::System,
            Severity::Info,
            ActionTaken::Logged,
            "System event".to_string(),
        ));
    }

    std::mem::forget(env);
    Arc::new(DaemonState::new(config, buffer))
}

async fn get(app: axum::Router, uri: &str) -> (StatusCode, String) {
    let response = app
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();

    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let text = String::from_utf8(body.to_vec()).unwrap();
    (status, text)
}

// ---------------------------------------------------------------------------
// /api/health
// ---------------------------------------------------------------------------

#[tokio::test]
async fn health_returns_ok() {
    let state = setup_state();
    let app = build_router(DashboardState::new(state));
    let (status, body) = get(app, "/api/health").await;

    assert_eq!(status, StatusCode::OK);
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(json["status"], "ok");
}

#[tokio::test]
async fn health_includes_timestamp() {
    let state = setup_state();
    let app = build_router(DashboardState::new(state));
    let (_, body) = get(app, "/api/health").await;

    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert!(json["timestamp"].is_string(), "Should include timestamp");
    let ts = json["timestamp"].as_str().unwrap();
    assert!(
        ts.contains("UTC") || ts.contains("T"),
        "Should be a valid timestamp format"
    );
}

// ---------------------------------------------------------------------------
// /api/status
// ---------------------------------------------------------------------------

#[tokio::test]
async fn status_returns_mode() {
    let state = setup_state();
    let app = build_router(DashboardState::new(state));
    let (status, body) = get(app, "/api/status").await;

    assert_eq!(status, StatusCode::OK);
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(json["mode"], "monitor");
}

#[tokio::test]
async fn status_lists_guards() {
    let state = setup_state();
    let app = build_router(DashboardState::new(state));
    let (_, body) = get(app, "/api/status").await;

    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    let guards = json["guards"].as_array().expect("guards should be array");
    assert_eq!(guards.len(), 5, "Should list all 5 guards");

    let names: Vec<&str> = guards.iter().map(|g| g["name"].as_str().unwrap()).collect();
    assert!(names.contains(&"fs_guard"));
    assert!(names.contains(&"cdp_proxy"));
    assert!(names.contains(&"net_guard"));
    assert!(names.contains(&"cmd_guard"));
    assert!(names.contains(&"pf_guard"));
}

// ---------------------------------------------------------------------------
// /api/events
// ---------------------------------------------------------------------------

#[tokio::test]
async fn events_returns_events() {
    let state = setup_state_with_events();
    let app = build_router(DashboardState::new(state));
    let (status, body) = get(app, "/api/events").await;

    assert_eq!(status, StatusCode::OK);
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    let events = json["events"].as_array().expect("events should be array");
    assert_eq!(events.len(), 3, "Should return all 3 events");
}

#[tokio::test]
async fn events_respects_limit() {
    let state = setup_state_with_events();
    let app = build_router(DashboardState::new(state));
    let (_, body) = get(app, "/api/events?limit=1").await;

    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    let events = json["events"].as_array().unwrap();
    assert_eq!(events.len(), 1, "limit=1 should return max 1 event");
}

#[tokio::test]
async fn events_filters_by_severity() {
    let state = setup_state_with_events();
    let app = build_router(DashboardState::new(state));
    let (_, body) = get(app, "/api/events?severity=critical").await;

    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    let events = json["events"].as_array().unwrap();
    assert_eq!(events.len(), 1, "Only 1 critical event");
    assert_eq!(events[0]["severity"], "critical");
}

#[tokio::test]
async fn events_filters_by_module() {
    let state = setup_state_with_events();
    let app = build_router(DashboardState::new(state));
    let (_, body) = get(app, "/api/events?module=fs_guard").await;

    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    let events = json["events"].as_array().unwrap();
    assert_eq!(events.len(), 1, "Only 1 fs_guard event");
    assert_eq!(events[0]["module"], "fs_guard");
}

// ---------------------------------------------------------------------------
// /api/config
// ---------------------------------------------------------------------------

#[tokio::test]
async fn config_redacts_slack_webhook() {
    let state = setup_state();
    let app = build_router(DashboardState::new(state));
    let (status, body) = get(app, "/api/config").await;

    assert_eq!(status, StatusCode::OK);
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();

    // The webhook URL should be redacted
    let webhook = json["alerting"]["slack"]["webhook_url"].as_str().unwrap();
    assert!(
        webhook.contains("***") || webhook == "REDACTED",
        "Webhook URL should be redacted, got: {}",
        webhook
    );
}

#[tokio::test]
async fn config_shows_enabled_status() {
    let state = setup_state();
    let app = build_router(DashboardState::new(state));
    let (_, body) = get(app, "/api/config").await;

    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    // Should show enabled flags
    assert!(json["fs_guard"]["enabled"].is_boolean());
    assert!(json["cdp_proxy"]["enabled"].is_boolean());
}

// ---------------------------------------------------------------------------
// parse_duration
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// GET / — Dashboard HTML
// ---------------------------------------------------------------------------

#[tokio::test]
async fn dashboard_root_returns_html() {
    let state = setup_state();
    let app = build_router(DashboardState::new(state));
    let (status, body) = get(app, "/").await;

    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("<html"), "Body should contain HTML markup");
    assert!(
        body.contains("CounterClaw"),
        "Body should contain CounterClaw title"
    );
}

#[tokio::test]
async fn dashboard_root_contains_api_references() {
    let state = setup_state();
    let app = build_router(DashboardState::new(state));
    let (_, body) = get(app, "/").await;

    assert!(
        body.contains("/api/status"),
        "HTML should reference /api/status endpoint"
    );
    assert!(
        body.contains("/api/events"),
        "HTML should reference /api/events endpoint"
    );
}

// ---------------------------------------------------------------------------
// GET /health, /status — shortcut routes
// ---------------------------------------------------------------------------

#[tokio::test]
async fn health_shortcut_works() {
    let state = setup_state();
    let app = build_router(DashboardState::new(state));
    let (status, body) = get(app, "/health").await;

    assert_eq!(status, StatusCode::OK);
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(json["status"], "ok");
}

#[tokio::test]
async fn status_shortcut_works() {
    let state = setup_state();
    let app = build_router(DashboardState::new(state));
    let (status, body) = get(app, "/status").await;

    assert_eq!(status, StatusCode::OK);
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(json["mode"], "monitor");
    assert!(json["guards"].is_array(), "Should include guards array");
}

// ---------------------------------------------------------------------------
// parse_duration
// ---------------------------------------------------------------------------

#[test]
fn parse_duration_hours() {
    let d = parse_duration("2h");
    assert!(d.is_some());
    assert_eq!(d.unwrap().num_hours(), 2);
}

#[test]
fn parse_duration_minutes() {
    let d = parse_duration("30m");
    assert!(d.is_some());
    assert_eq!(d.unwrap().num_minutes(), 30);
}

#[test]
fn parse_duration_invalid_none() {
    assert!(parse_duration("abc").is_none());
    assert!(parse_duration("").is_none());
}
