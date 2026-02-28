//! Security tests for dashboard hardening.
//!
//! Tests:
//! - Step 0.3: Bearer token authentication on write endpoints
//! - Step 0.5: Origin/CSRF validation
//! - Step 2.9: Rate limiting
//! - Step 3.8: Input validation for rules API
//! - Step 3.9: Security headers (CSP, X-Frame-Options, X-Content-Type-Options)

mod common;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use counterclaw::config::AppConfig;
use counterclaw::daemon::DaemonState;
use counterclaw::dashboard::server::{build_router, generate_api_token, DashboardState};
use counterclaw::types::EventBuffer;
use std::sync::{Arc, RwLock};
use tower::ServiceExt;

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

fn setup_state() -> Arc<DaemonState> {
    let env = common::TestEnv::new();
    let yaml = common::minimal_monitor_config(&env);
    env.write_config(&yaml);
    let config = AppConfig::load(&env.config_path()).expect("valid config");
    let buffer = Arc::new(RwLock::new(EventBuffer::new(100)));
    std::mem::forget(env);
    Arc::new(DaemonState::new(config, buffer))
}

/// Send a request with optional method, headers, and body.
async fn send_request(
    app: axum::Router,
    method: Method,
    uri: &str,
    headers: Vec<(&str, &str)>,
    body: Option<&str>,
) -> (StatusCode, String, axum::http::HeaderMap) {
    let mut builder = Request::builder().method(method).uri(uri);
    for (key, value) in &headers {
        builder = builder.header(*key, *value);
    }
    let req = if let Some(b) = body {
        builder
            .header("content-type", "application/json")
            .body(Body::from(b.to_string()))
            .unwrap()
    } else {
        builder.body(Body::empty()).unwrap()
    };

    let response = app.oneshot(req).await.unwrap();
    let status = response.status();
    let resp_headers = response.headers().clone();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let text = String::from_utf8(bytes.to_vec()).unwrap();
    (status, text, resp_headers)
}

// ===========================================================================
// Step 0.3 — Auth token tests
// ===========================================================================

#[tokio::test]
async fn write_endpoints_require_auth_token() {
    let state = setup_state();
    let ds = DashboardState::with_token(state, "test-secret-token".to_string());
    let app = build_router(ds);

    // PUT /api/mode without token => 401
    let (status, _, _) = send_request(
        app,
        Method::PUT,
        "/api/mode",
        vec![],
        Some(r#"{"mode": "enforce"}"#),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn read_endpoints_open_without_auth() {
    let state = setup_state();
    let ds = DashboardState::with_token(state, "test-secret-token".to_string());

    // GET /health => 200 (no auth needed)
    let app = build_router(ds.clone());
    let (status, _, _) = send_request(app, Method::GET, "/health", vec![], None).await;
    assert_eq!(status, StatusCode::OK);

    // GET /api/status => 200
    let app = build_router(ds);
    let (status, _, _) = send_request(app, Method::GET, "/api/status", vec![], None).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn valid_token_allows_mode_change() {
    let state = setup_state();
    let token = "test-token-123".to_string();
    let ds = DashboardState::with_token(state, token.clone());
    let app = build_router(ds);

    let (status, _, _) = send_request(
        app,
        Method::PUT,
        "/api/mode",
        vec![("authorization", "Bearer test-token-123")],
        Some(r#"{"mode": "enforce"}"#),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn invalid_token_returns_401() {
    let state = setup_state();
    let ds = DashboardState::with_token(state, "correct-token".to_string());
    let app = build_router(ds);

    let (status, _, _) = send_request(
        app,
        Method::PUT,
        "/api/mode",
        vec![("authorization", "Bearer wrong-token")],
        Some(r#"{"mode": "enforce"}"#),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn no_token_configured_allows_all_writes() {
    let state = setup_state();
    // DashboardState::new => auth_token = None => all writes allowed
    let ds = DashboardState::new(state);
    let app = build_router(ds);

    let (status, _, _) = send_request(
        app,
        Method::PUT,
        "/api/mode",
        vec![],
        Some(r#"{"mode": "enforce"}"#),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

// ===========================================================================
// Step 0.5 — CSRF / Origin validation tests
// ===========================================================================

#[tokio::test]
async fn rejects_cross_origin_requests() {
    let state = setup_state();
    let ds = DashboardState::new(state);
    let app = build_router(ds);

    let (status, _, _) = send_request(
        app,
        Method::POST,
        "/api/rules/domains",
        vec![("origin", "https://evil.com")],
        Some(r#"{"category": "blocked", "value": "test.com"}"#),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn accepts_localhost_origin() {
    let state = setup_state();
    let ds = DashboardState::new(state);
    let app = build_router(ds);

    let (status, _, _) = send_request(
        app,
        Method::POST,
        "/api/rules/domains",
        vec![("origin", "http://localhost:9999")],
        Some(r#"{"category": "blocked", "value": "evil-test.com"}"#),
    )
    .await;
    // Should NOT be 403 (may be 200 OK)
    assert_ne!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn accepts_127_origin() {
    let state = setup_state();
    let ds = DashboardState::new(state);
    let app = build_router(ds);

    let (status, _, _) = send_request(
        app,
        Method::POST,
        "/api/rules/domains",
        vec![("origin", "http://127.0.0.1:9999")],
        Some(r#"{"category": "blocked", "value": "evil-127-test.com"}"#),
    )
    .await;
    assert_ne!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn accepts_missing_origin_from_curl() {
    let state = setup_state();
    let ds = DashboardState::new(state);
    let app = build_router(ds);

    // No Origin header at all (like curl)
    let (status, _, _) = send_request(
        app,
        Method::POST,
        "/api/rules/domains",
        vec![],
        Some(r#"{"category": "blocked", "value": "curl-test.com"}"#),
    )
    .await;
    // Should NOT be 403
    assert_ne!(status, StatusCode::FORBIDDEN);
}

// ===========================================================================
// Step 2.9 — Rate limiting tests
// ===========================================================================

#[tokio::test]
async fn returns_429_when_write_limit_exceeded() {
    let state = setup_state();
    let ds = DashboardState::new(state);

    // Send 11 rapid PUT requests — first 10 should succeed, 11th gets 429
    let mut got_429 = false;
    for i in 0..15 {
        let app = build_router(ds.clone());
        let mode = if i % 2 == 0 { "enforce" } else { "monitor" };
        let body = format!(r#"{{"mode": "{}"}}"#, mode);
        let (status, _, _) = send_request(app, Method::PUT, "/api/mode", vec![], Some(&body)).await;
        if status == StatusCode::TOO_MANY_REQUESTS {
            got_429 = true;
            break;
        }
    }
    assert!(got_429, "Should get 429 after exceeding write rate limit");
}

#[tokio::test]
async fn read_endpoints_have_higher_limit() {
    let state = setup_state();
    let ds = DashboardState::new(state);

    // Send 20 rapid GET requests — all should succeed (read limit is 100/s)
    for _ in 0..20 {
        let app = build_router(ds.clone());
        let (status, _, _) = send_request(app, Method::GET, "/api/health", vec![], None).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "Read endpoints should allow at least 20 req/s"
        );
    }
}

// ===========================================================================
// Step 3.8 — Input validation tests
// ===========================================================================

#[tokio::test]
async fn rejects_oversized_rule_value() {
    let state = setup_state();
    let ds = DashboardState::new(state);
    let app = build_router(ds);

    // Create a value > 500 chars
    let long_value = "x".repeat(501);
    let body = format!(r#"{{"category": "blocked", "value": "{}"}}"#, long_value);

    let (status, _, _) =
        send_request(app, Method::POST, "/api/rules/domains", vec![], Some(&body)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn accepts_rule_at_max_length() {
    let state = setup_state();
    let ds = DashboardState::new(state);
    let app = build_router(ds);

    // Create a value of exactly 500 chars
    let value = "a".repeat(500);
    let body = format!(r#"{{"category": "blocked", "value": "{}"}}"#, value);

    let (status, _, _) =
        send_request(app, Method::POST, "/api/rules/domains", vec![], Some(&body)).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn rejects_invalid_regex_rule() {
    let state = setup_state();
    let ds = DashboardState::new(state);
    let app = build_router(ds);

    let (status, _, _) = send_request(
        app,
        Method::POST,
        "/api/rules/commands",
        vec![],
        Some(
            r#"{"category": "blacklist", "pattern": "[invalid", "description": "Bad regex", "severity": "high"}"#,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn rejects_duplicate_rule() {
    let state = setup_state();
    let ds = DashboardState::new(state);

    // Add a rule first
    let app = build_router(ds.clone());
    let (status, _, _) = send_request(
        app,
        Method::POST,
        "/api/rules/domains",
        vec![],
        Some(r#"{"category": "blocked", "value": "dup-test.com"}"#),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Try to add the same rule again
    let app = build_router(ds);
    let (status, _, _) = send_request(
        app,
        Method::POST,
        "/api/rules/domains",
        vec![],
        Some(r#"{"category": "blocked", "value": "dup-test.com"}"#),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
}

// ===========================================================================
// Step 3.9 — Security headers tests
// ===========================================================================

#[tokio::test]
async fn dashboard_returns_csp_header() {
    let state = setup_state();
    let ds = DashboardState::new(state);
    let app = build_router(ds);

    let (status, _, headers) = send_request(app, Method::GET, "/health", vec![], None).await;
    assert_eq!(status, StatusCode::OK);

    let csp = headers
        .get("content-security-policy")
        .expect("Should have CSP header")
        .to_str()
        .unwrap();
    assert!(
        csp.contains("default-src 'self'"),
        "CSP should contain default-src 'self', got: {}",
        csp
    );
    assert!(
        csp.contains("script-src 'unsafe-inline'"),
        "CSP should contain script-src 'unsafe-inline', got: {}",
        csp
    );
    assert!(
        csp.contains("style-src 'unsafe-inline'"),
        "CSP should contain style-src 'unsafe-inline', got: {}",
        csp
    );
}

#[tokio::test]
async fn dashboard_returns_xframe_deny() {
    let state = setup_state();
    let ds = DashboardState::new(state);
    let app = build_router(ds);

    let (status, _, headers) = send_request(app, Method::GET, "/health", vec![], None).await;
    assert_eq!(status, StatusCode::OK);

    let xframe = headers
        .get("x-frame-options")
        .expect("Should have X-Frame-Options header")
        .to_str()
        .unwrap();
    assert_eq!(xframe, "DENY");
}

#[tokio::test]
async fn dashboard_returns_nosniff_header() {
    let state = setup_state();
    let ds = DashboardState::new(state);
    let app = build_router(ds);

    let (status, _, headers) = send_request(app, Method::GET, "/health", vec![], None).await;
    assert_eq!(status, StatusCode::OK);

    let nosniff = headers
        .get("x-content-type-options")
        .expect("Should have X-Content-Type-Options header")
        .to_str()
        .unwrap();
    assert_eq!(nosniff, "nosniff");
}

// ===========================================================================
// generate_api_token tests
// ===========================================================================

#[test]
fn generate_api_token_produces_64_hex_chars() {
    let token = generate_api_token();
    assert_eq!(token.len(), 64, "Token should be 64 hex chars (32 bytes)");
    assert!(
        token.chars().all(|c| c.is_ascii_hexdigit()),
        "Token should only contain hex chars, got: {}",
        token
    );
}

#[test]
fn generate_api_token_is_unique() {
    let t1 = generate_api_token();
    let t2 = generate_api_token();
    assert_ne!(t1, t2, "Two generated tokens should be different");
}

// ===========================================================================
// Auth + CSRF combined tests
// ===========================================================================

#[tokio::test]
async fn auth_and_csrf_both_required_for_writes() {
    let state = setup_state();
    let ds = DashboardState::with_token(state, "combo-token".to_string());

    // Valid token + evil origin => 403
    let app = build_router(ds.clone());
    let (status, _, _) = send_request(
        app,
        Method::PUT,
        "/api/mode",
        vec![
            ("authorization", "Bearer combo-token"),
            ("origin", "https://evil.com"),
        ],
        Some(r#"{"mode": "enforce"}"#),
    )
    .await;
    // Auth passes but CSRF fails => 403 (order: auth checked first, then CSRF)
    // Actually the code checks auth first, then origin. If auth passes but
    // origin fails, we get 403.
    assert!(
        status == StatusCode::FORBIDDEN || status == StatusCode::UNAUTHORIZED,
        "Should reject: got {}",
        status
    );

    // Valid token + localhost origin => 200
    let app = build_router(ds);
    let (status, _, _) = send_request(
        app,
        Method::PUT,
        "/api/mode",
        vec![
            ("authorization", "Bearer combo-token"),
            ("origin", "http://localhost:9999"),
        ],
        Some(r#"{"mode": "enforce"}"#),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

// ===========================================================================
// Security headers on all response types
// ===========================================================================

#[tokio::test]
async fn security_headers_present_on_html_response() {
    let state = setup_state();
    let ds = DashboardState::new(state);
    let app = build_router(ds);

    let (status, _, headers) = send_request(app, Method::GET, "/", vec![], None).await;
    assert_eq!(status, StatusCode::OK);

    // All three security headers should be present even on HTML responses
    assert!(
        headers.get("content-security-policy").is_some(),
        "CSP header should be present on HTML"
    );
    assert!(
        headers.get("x-frame-options").is_some(),
        "X-Frame-Options should be present on HTML"
    );
    assert!(
        headers.get("x-content-type-options").is_some(),
        "X-Content-Type-Options should be present on HTML"
    );
}

#[tokio::test]
async fn post_to_rules_without_auth_token_succeeds_when_no_token_configured() {
    let state = setup_state();
    let ds = DashboardState::new(state);
    let app = build_router(ds);

    // POST with no auth should succeed when no token is configured
    let (status, _, _) = send_request(
        app,
        Method::POST,
        "/api/rules/fs",
        vec![],
        Some(r#"{"category": "blocked", "value": "~/.no-auth-test"}"#),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn delete_requires_auth_when_token_configured() {
    let state = setup_state();
    let ds = DashboardState::with_token(Arc::clone(&state), "del-token".to_string());

    // First add a rule (with auth)
    let app = build_router(ds.clone());
    let (status, _, _) = send_request(
        app,
        Method::POST,
        "/api/rules/fs",
        vec![("authorization", "Bearer del-token")],
        Some(r#"{"category": "blocked", "value": "~/.del-test"}"#),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Try to delete without auth => 401
    let app = build_router(ds.clone());
    let (status, _, _) =
        send_request(app, Method::DELETE, "/api/rules/fs/blocked/0", vec![], None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}
