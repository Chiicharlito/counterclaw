//! Security Audit #2 — Phase 1: Guards bypass tests
//!
//! V4: Glob case-insensitive sur macOS
//! V5: CDP content buffer sliding window
//! V6: Config reload propage aux guards
//! V7: Validation sémantique des règles API
//! V8: Supprimer env var pour Slack webhook

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use counterclaw::config::AppConfig;
use counterclaw::daemon::DaemonState;
use counterclaw::dashboard::server::{build_router, generate_api_token, DashboardState};
use counterclaw::guards::cdp_proxy::{CdpSessionState, ContentInspector};
use counterclaw::guards::fs_guard::{PathMatcher, PathVerdict};
use counterclaw::types::{EventBuffer, OperationMode};
use std::sync::{Arc, RwLock};
use tower::ServiceExt;

// =========================================================================
// V4 — Glob case-insensitive sur macOS
// =========================================================================

#[cfg(target_os = "macos")]
#[test]
fn blocks_ssh_uppercase_on_macos() {
    let matcher = PathMatcher::new(vec!["~/.ssh".to_string()], vec![], vec![]);
    let home = dirs::home_dir().expect("home dir");
    let upper_ssh = home.join(".SSH").join("id_rsa");
    let verdict = matcher.check(&upper_ssh, &OperationMode::Enforce);
    assert_eq!(
        verdict,
        PathVerdict::Blocked,
        "~/.SSH/id_rsa should be blocked on macOS (case-insensitive)"
    );
}

#[cfg(target_os = "macos")]
#[test]
fn glob_pattern_case_insensitive_on_macos() {
    let matcher = PathMatcher::new(vec!["~/.env.*".to_string()], vec![], vec![]);
    let home = dirs::home_dir().expect("home dir");
    let upper_env = home.join(".ENV.production");
    let verdict = matcher.check(&upper_env, &OperationMode::Enforce);
    assert_eq!(
        verdict,
        PathVerdict::Blocked,
        "~/.ENV.production should be blocked on macOS (case-insensitive glob)"
    );
}

#[cfg(target_os = "macos")]
#[test]
fn exact_path_case_insensitive_on_macos() {
    let matcher = PathMatcher::new(vec!["~/.aws".to_string()], vec![], vec![]);
    let home = dirs::home_dir().expect("home dir");
    let upper_aws = home.join(".AWS").join("credentials");
    let verdict = matcher.check(&upper_aws, &OperationMode::Enforce);
    assert_eq!(
        verdict,
        PathVerdict::Blocked,
        "~/.AWS/credentials should be blocked on macOS (case-insensitive exact)"
    );
}

// =========================================================================
// V5 — CDP content buffer sliding window (overlap)
// =========================================================================

#[test]
fn detects_api_key_split_across_messages() {
    let config = counterclaw::config::ContentInspectionConfig {
        enabled: true,
        patterns: vec![counterclaw::config::ContentPatternConfig {
            name: "api_key".to_string(),
            regex: r"AKIA[0-9A-Z]{16}".to_string(),
            severity: "critical".to_string(),
            action: "block".to_string(),
        }],
    };
    let inspector = ContentInspector::new(&config);
    let mut state = CdpSessionState::new();

    // Split the key across two messages
    let key = "AKIA1234567890ABCDEF";
    let part1 = &key[..4]; // "AKIA"
    let part2 = &key[4..]; // "1234567890ABCDEF"

    let msg1 = format!("some data before {}", part1);
    state.push_content(&msg1);

    let msg2 = format!("{}some data after", part2);
    state.push_content(&msg2);

    let combined = state.get_sliding_window_content();
    let matches = inspector.inspect(&combined);

    assert!(
        !matches.is_empty(),
        "Should detect API key split across messages. Combined: '{}'",
        combined
    );
}

#[test]
fn detects_secret_at_buffer_boundary() {
    let config = counterclaw::config::ContentInspectionConfig {
        enabled: true,
        patterns: vec![counterclaw::config::ContentPatternConfig {
            name: "password".to_string(),
            regex: r"password\s*=\s*\S+".to_string(),
            severity: "high".to_string(),
            action: "alert".to_string(),
        }],
    };
    let inspector = ContentInspector::new(&config);
    let mut state = CdpSessionState::new();

    state.push_content("data before pass");
    state.push_content("word = secret123 after data");

    let combined = state.get_sliding_window_content();
    let matches = inspector.inspect(&combined);

    assert!(
        !matches.is_empty(),
        "Should detect 'password = secret123' at buffer boundary. Combined: '{}'",
        combined
    );
}

#[test]
fn content_buffer_overlap_preserves_context() {
    let mut state = CdpSessionState::new();

    state.push_content("first message content");
    state.push_content("second message content");
    state.push_content("third message content");

    let sliding = state.get_sliding_window_content();
    assert!(
        sliding.contains("third message content"),
        "Sliding window should contain latest content"
    );
    assert!(
        sliding.contains("second message content"),
        "Sliding window should include overlap from previous message"
    );
}

// =========================================================================
// V6 — Config reload propage aux guards
// =========================================================================

#[test]
fn guard_uses_updated_rules_after_reload() {
    let env = common::TestEnv::new();
    let yaml = common::minimal_monitor_config(&env);
    env.write_config(&yaml);
    let config = AppConfig::load(&env.config_path()).expect("load config");
    let buffer = Arc::new(RwLock::new(EventBuffer::new(100)));
    let state = DaemonState::new(config, buffer);

    {
        let cfg = state.config.read().unwrap();
        assert!(cfg.cdp_proxy.domains.blocked.is_empty());
    }

    // Reload with blocked domains
    let yaml2 =
        common::minimal_monitor_config(&env).replace("blocked: []", "blocked:\n    - evil.com");
    std::fs::write(env.config_path(), &yaml2).unwrap();
    state.reload_config(&env.config_path()).unwrap();

    let cfg = state.config.read().unwrap();
    assert!(
        cfg.cdp_proxy
            .domains
            .blocked
            .contains(&"evil.com".to_string()),
        "Config should have evil.com in blocked domains after reload"
    );
}

#[test]
fn config_reload_propagates_to_fs_guard_rules() {
    let env = common::TestEnv::new();
    let yaml = common::minimal_monitor_config(&env);
    env.write_config(&yaml);
    let config = AppConfig::load(&env.config_path()).expect("load config");
    let buffer = Arc::new(RwLock::new(EventBuffer::new(100)));
    let state = DaemonState::new(config, buffer);

    let yaml2 = common::minimal_monitor_config(&env)
        .replace("blocked_paths: []", "blocked_paths:\n    - /secret/path");
    std::fs::write(env.config_path(), &yaml2).unwrap();
    state.reload_config(&env.config_path()).unwrap();

    let cfg = state.config.read().unwrap();
    assert!(
        cfg.fs_guard
            .blocked_paths
            .contains(&"/secret/path".to_string()),
        "FS guard should see new blocked path after reload"
    );
}

#[test]
fn guard_blocks_new_domain_after_reload() {
    use counterclaw::guards::cdp_proxy::DomainMatcher;

    let env = common::TestEnv::new();
    let yaml = common::minimal_monitor_config(&env);
    env.write_config(&yaml);
    let config = AppConfig::load(&env.config_path()).expect("load config");
    let buffer = Arc::new(RwLock::new(EventBuffer::new(100)));
    let state = DaemonState::new(config, buffer);

    // Initially not blocked
    {
        let cfg = state.config.read().unwrap();
        let matcher = DomainMatcher::new(&cfg.cdp_proxy.domains);
        let verdict = matcher.check("evil.com", &OperationMode::Enforce);
        assert_ne!(
            verdict,
            counterclaw::guards::cdp_proxy::DomainVerdict::Blocked,
            "evil.com should NOT be blocked before reload"
        );
    }

    // Reload with evil.com blocked
    let yaml2 = common::minimal_monitor_config(&env).replace(
        "blocked: []\n    allowed: []\n    require_approval: []\n    default_policy: allow",
        "blocked:\n      - evil.com\n    allowed: []\n    require_approval: []\n    default_policy: allow",
    );
    std::fs::write(env.config_path(), &yaml2).unwrap();
    state.reload_config(&env.config_path()).unwrap();

    {
        let cfg = state.config.read().unwrap();
        let matcher = DomainMatcher::new(&cfg.cdp_proxy.domains);
        let verdict = matcher.check("evil.com", &OperationMode::Enforce);
        assert_eq!(
            verdict,
            counterclaw::guards::cdp_proxy::DomainVerdict::Blocked,
            "evil.com should be blocked after reload"
        );
    }
}

// =========================================================================
// V7 — Validation sémantique des règles API
// =========================================================================

fn make_test_dashboard_state() -> DashboardState {
    let env = common::TestEnv::new();
    let yaml = common::minimal_monitor_config(&env);
    env.write_config(&yaml);
    let config = AppConfig::load(&env.config_path()).expect("load config");
    let buffer = Arc::new(RwLock::new(EventBuffer::new(100)));
    let state = Arc::new(DaemonState::new(config, buffer));
    let token = generate_api_token();
    std::mem::forget(env);
    DashboardState::with_token(state, token)
}

#[tokio::test]
async fn rejects_invalid_domain_format() {
    let state = make_test_dashboard_state();
    let token = state.auth_token.clone().unwrap();
    let router = build_router(state);

    let body = serde_json::json!({
        "category": "blocked",
        "value": "not a valid domain"
    });

    let req = Request::builder()
        .method("POST")
        .uri("/api/rules/domains")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {}", token))
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap();

    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "Should reject domain with spaces"
    );
}

#[tokio::test]
async fn rejects_invalid_path_format() {
    let state = make_test_dashboard_state();
    let token = state.auth_token.clone().unwrap();
    let router = build_router(state);

    let body = serde_json::json!({
        "category": "blocked",
        "value": "relative/path/here"
    });

    let req = Request::builder()
        .method("POST")
        .uri("/api/rules/fs")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {}", token))
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap();

    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "Should reject relative path"
    );
}

#[tokio::test]
async fn rejects_invalid_regex_pattern() {
    let state = make_test_dashboard_state();
    let token = state.auth_token.clone().unwrap();
    let router = build_router(state);

    let body = serde_json::json!({
        "category": "blacklist",
        "pattern": "[invalid(regex",
        "description": "test"
    });

    let req = Request::builder()
        .method("POST")
        .uri("/api/rules/commands")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {}", token))
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap();

    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "Should reject invalid regex pattern"
    );
}

#[tokio::test]
async fn accepts_valid_domain_format() {
    let state = make_test_dashboard_state();
    let token = state.auth_token.clone().unwrap();
    let router = build_router(state);

    let body = serde_json::json!({
        "category": "blocked",
        "value": "evil.example.com"
    });

    let req = Request::builder()
        .method("POST")
        .uri("/api/rules/domains")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {}", token))
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap();

    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "Should accept valid domain");
}

#[tokio::test]
async fn accepts_valid_absolute_path() {
    let state = make_test_dashboard_state();
    let token = state.auth_token.clone().unwrap();
    let router = build_router(state);

    let body = serde_json::json!({
        "category": "blocked",
        "value": "/etc/secrets/keys"
    });

    let req = Request::builder()
        .method("POST")
        .uri("/api/rules/fs")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {}", token))
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap();

    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "Should accept valid absolute path"
    );
}

// =========================================================================
// V8 — Supprimer env var pour Slack webhook
// =========================================================================

#[test]
fn slack_url_not_read_from_env_var() {
    std::env::set_var(
        "COUNTERCLAW_SLACK_WEBHOOK",
        "https://evil.attacker.com/webhook",
    );

    let env = common::TestEnv::new();
    let yaml = common::minimal_monitor_config(&env);
    env.write_config(&yaml);
    let config = AppConfig::load(&env.config_path()).expect("load config");

    let url = config.slack_webhook_url();
    assert_ne!(
        url, "https://evil.attacker.com/webhook",
        "Should NOT read Slack webhook from env var"
    );

    std::env::remove_var("COUNTERCLAW_SLACK_WEBHOOK");
}

#[test]
fn slack_url_from_config_only() {
    let env = common::TestEnv::new();
    let yaml = common::minimal_monitor_config(&env);
    env.write_config(&yaml);
    let config = AppConfig::load(&env.config_path()).expect("load config");

    let url = config.slack_webhook_url();
    assert_eq!(
        url, "https://hooks.slack.com/services/XXXX/YYYY/ZZZZ",
        "Should read Slack webhook from config file only"
    );
}
