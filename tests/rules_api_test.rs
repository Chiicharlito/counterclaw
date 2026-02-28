//! Tests pour l'API REST CRUD des règles (Étape 3).
//!
//! Endpoints testés :
//! - GET /api/rules — liste toutes les règles
//! - GET /api/rules/{guard} — règles d'un guard
//! - POST /api/rules/{guard} — ajouter une règle
//! - PUT /api/rules/{guard}/{index} — modifier une règle
//! - DELETE /api/rules/{guard}/{index} — supprimer une règle
//! - PUT /api/mode — changer le mode

mod common;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use counterclaw::config::AppConfig;
use counterclaw::daemon::DaemonState;
use counterclaw::dashboard::server::build_router;
use counterclaw::types::EventBuffer;
use std::sync::{Arc, RwLock};
use tower::ServiceExt;

fn setup_state_with_env() -> (Arc<DaemonState>, common::TestEnv) {
    let env = common::TestEnv::new();
    let yaml = common::minimal_monitor_config(&env);
    env.write_config(&yaml);
    let config = AppConfig::load(&env.config_path()).expect("valid config");
    let buffer = Arc::new(RwLock::new(EventBuffer::new(100)));
    let state = Arc::new(DaemonState::new(config, buffer));
    (state, env)
}

async fn request(
    app: axum::Router,
    method: Method,
    uri: &str,
    body: Option<&str>,
) -> (StatusCode, String) {
    let req = Request::builder().method(method).uri(uri);
    let req = if let Some(b) = body {
        req.header("content-type", "application/json")
            .body(Body::from(b.to_string()))
            .unwrap()
    } else {
        req.body(Body::empty()).unwrap()
    };

    let response = app.oneshot(req).await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let text = String::from_utf8(bytes.to_vec()).unwrap();
    (status, text)
}

// ===========================================================================
// 1. GET /api/rules — liste toutes les règles
// ===========================================================================

#[tokio::test]
async fn get_all_rules_returns_all_guards() {
    let (state, _env) = setup_state_with_env();
    let app = build_router(state);
    let (status, body) = request(app, Method::GET, "/api/rules", None).await;

    assert_eq!(status, StatusCode::OK);
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    // Doit contenir les 4 guards
    assert!(json["fs"].is_object(), "Should have fs section");
    assert!(json["domains"].is_object(), "Should have domains section");
    assert!(json["egress"].is_object(), "Should have egress section");
    assert!(json["commands"].is_object(), "Should have commands section");
}

// ===========================================================================
// 2. GET /api/rules/{guard} — règles d'un guard
// ===========================================================================

#[tokio::test]
async fn get_fs_rules_returns_categories() {
    let (state, _env) = setup_state_with_env();
    let app = build_router(state);
    let (status, body) = request(app, Method::GET, "/api/rules/fs", None).await;

    assert_eq!(status, StatusCode::OK);
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert!(json["blocked"].is_array());
    assert!(json["read_only"].is_array());
    assert!(json["allowed"].is_array());
}

// ===========================================================================
// 3. POST /api/rules/{guard} — ajouter une règle
// ===========================================================================

#[tokio::test]
async fn add_fs_rule_succeeds() {
    let (state, _env) = setup_state_with_env();
    let app = build_router(state);
    let (status, _) = request(
        app,
        Method::POST,
        "/api/rules/fs",
        Some(r#"{"category": "blocked", "value": "~/.env"}"#),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn add_fs_rule_appears_in_config() {
    let (state, _env) = setup_state_with_env();

    // Ajouter une règle
    let app = build_router(Arc::clone(&state));
    let (status, _) = request(
        app,
        Method::POST,
        "/api/rules/fs",
        Some(r#"{"category": "blocked", "value": "~/.secret"}"#),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Vérifier qu'elle apparaît dans la config
    let config = state.config.read().unwrap();
    assert!(
        config
            .fs_guard
            .blocked_paths
            .contains(&"~/.secret".to_string()),
        "New path should be in blocked_paths"
    );
}

#[tokio::test]
async fn add_domain_rule_succeeds() {
    let (state, _env) = setup_state_with_env();
    let app = build_router(state);
    let (status, _) = request(
        app,
        Method::POST,
        "/api/rules/domains",
        Some(r#"{"category": "blocked", "value": "evil.com"}"#),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn add_command_rule_succeeds() {
    let (state, _env) = setup_state_with_env();
    let app = build_router(state);
    let (status, _) = request(
        app,
        Method::POST,
        "/api/rules/commands",
        Some(r#"{"category": "blacklist", "pattern": "docker\\s+push", "description": "Docker push", "severity": "high"}"#),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn add_egress_rule_succeeds() {
    let (state, _env) = setup_state_with_env();
    let app = build_router(state);
    let (status, _) = request(
        app,
        Method::POST,
        "/api/rules/egress",
        Some(r#"{"category": "allowed", "value": "api.example.com"}"#),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
}

// ===========================================================================
// 4. DELETE /api/rules/{guard}/{index} — supprimer une règle
// ===========================================================================

#[tokio::test]
async fn delete_fs_rule_succeeds() {
    let (state, _env) = setup_state_with_env();

    // D'abord ajouter une règle
    let app = build_router(Arc::clone(&state));
    request(
        app,
        Method::POST,
        "/api/rules/fs",
        Some(r#"{"category": "blocked", "value": "~/.to_delete"}"#),
    )
    .await;

    // Vérifier qu'elle est là
    {
        let config = state.config.read().unwrap();
        assert!(config
            .fs_guard
            .blocked_paths
            .contains(&"~/.to_delete".to_string()));
    }

    // Supprimer
    let app = build_router(Arc::clone(&state));
    let (status, _) = request(app, Method::DELETE, "/api/rules/fs/blocked/0", None).await;
    assert_eq!(status, StatusCode::OK);

    // Vérifier suppression
    let config = state.config.read().unwrap();
    assert!(
        !config
            .fs_guard
            .blocked_paths
            .contains(&"~/.to_delete".to_string()),
        "Deleted path should not be in blocked_paths"
    );
}

// ===========================================================================
// 5. PUT /api/mode — changer le mode
// ===========================================================================

#[tokio::test]
async fn change_mode_succeeds() {
    let (state, _env) = setup_state_with_env();
    let app = build_router(Arc::clone(&state));

    assert_eq!(state.mode().to_string(), "monitor");

    let (status, _) = request(
        app,
        Method::PUT,
        "/api/mode",
        Some(r#"{"mode": "paranoid"}"#),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(state.mode().to_string(), "paranoid");
}

#[tokio::test]
async fn change_mode_invalid_rejected() {
    let (state, _env) = setup_state_with_env();
    let app = build_router(state);

    let (status, _) = request(
        app,
        Method::PUT,
        "/api/mode",
        Some(r#"{"mode": "INVALID"}"#),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
}

// ===========================================================================
// 6. Validation — regex invalide rejetée
// ===========================================================================

#[tokio::test]
async fn invalid_regex_rejected() {
    let (state, _env) = setup_state_with_env();
    let app = build_router(state);

    let (status, _) = request(
        app,
        Method::POST,
        "/api/rules/commands",
        Some(r#"{"category": "blacklist", "pattern": "[invalid", "description": "Bad regex", "severity": "high"}"#),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
}

// ===========================================================================
// 7. Guard inconnu → 404
// ===========================================================================

#[tokio::test]
async fn unknown_guard_returns_404() {
    let (state, _env) = setup_state_with_env();
    let app = build_router(state);

    let (status, _) = request(app, Method::GET, "/api/rules/unknown", None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}
