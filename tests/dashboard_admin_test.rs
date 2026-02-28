//! Tests pour le dashboard HTML d'administration (Étape 4).
//!
//! Vérifie que le dashboard contient :
//! - Des onglets (Aperçu, Fichiers, Domaines, Réseau, Commandes)
//! - Des formulaires d'ajout de règle
//! - Un sélecteur de mode
//! - Un logo SVG
//! - Des références aux API rules/mode
//! - Un endpoint SSE pour les mises à jour temps réel

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use counterclaw::config::AppConfig;
use counterclaw::daemon::DaemonState;
use counterclaw::dashboard::server::build_router;
use counterclaw::types::EventBuffer;
use std::sync::{Arc, RwLock};
use tower::ServiceExt;

fn setup_state() -> Arc<DaemonState> {
    let env = common::TestEnv::new();
    let yaml = common::minimal_monitor_config(&env);
    env.write_config(&yaml);
    let config = AppConfig::load(&env.config_path()).expect("valid config");
    let buffer = Arc::new(RwLock::new(EventBuffer::new(100)));
    std::mem::forget(env);
    Arc::new(DaemonState::new(config, buffer))
}

async fn get_html(app: axum::Router, uri: &str) -> (StatusCode, String) {
    let response = app
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, String::from_utf8(body.to_vec()).unwrap())
}

// ===========================================================================
// 1. Le dashboard contient des onglets
// ===========================================================================

#[tokio::test]
async fn dashboard_html_contains_tabs() {
    let state = setup_state();
    let app = build_router(state);
    let (status, body) = get_html(app, "/").await;

    assert_eq!(status, StatusCode::OK);
    // Doit contenir les onglets pour chaque section
    assert!(body.contains("tab-overview"), "Should have overview tab");
    assert!(body.contains("tab-fs"), "Should have fs tab");
    assert!(body.contains("tab-domains"), "Should have domains tab");
    assert!(body.contains("tab-egress"), "Should have egress tab");
    assert!(body.contains("tab-commands"), "Should have commands tab");
}

// ===========================================================================
// 2. Le dashboard contient des formulaires d'ajout
// ===========================================================================

#[tokio::test]
async fn dashboard_html_contains_add_forms() {
    let state = setup_state();
    let app = build_router(state);
    let (_, body) = get_html(app, "/").await;

    // Doit contenir des boutons/formulaires d'ajout
    assert!(
        body.contains("addRule") || body.contains("add-rule") || body.contains("Add"),
        "Should have add rule functionality"
    );
}

// ===========================================================================
// 3. Le dashboard contient un sélecteur de mode
// ===========================================================================

#[tokio::test]
async fn dashboard_html_contains_mode_selector() {
    let state = setup_state();
    let app = build_router(state);
    let (_, body) = get_html(app, "/").await;

    assert!(
        body.contains("monitor") && body.contains("enforce") && body.contains("paranoid"),
        "Should have all three mode options"
    );
    assert!(
        body.contains("/api/mode"),
        "Should reference the mode change API"
    );
}

// ===========================================================================
// 4. Le dashboard contient un logo SVG
// ===========================================================================

#[tokio::test]
async fn dashboard_html_contains_logo() {
    let state = setup_state();
    let app = build_router(state);
    let (_, body) = get_html(app, "/").await;

    assert!(
        body.contains("<svg") || body.contains("data:image/svg"),
        "Should contain an SVG logo"
    );
}

// ===========================================================================
// 5. Le dashboard référence les API rules
// ===========================================================================

#[tokio::test]
async fn dashboard_html_references_rules_api() {
    let state = setup_state();
    let app = build_router(state);
    let (_, body) = get_html(app, "/").await;

    assert!(
        body.contains("/api/rules"),
        "Should reference /api/rules endpoint"
    );
}

// ===========================================================================
// 6. Le dashboard est XSS-safe (utilise textContent, pas innerHTML)
// ===========================================================================

#[tokio::test]
async fn dashboard_html_xss_safe() {
    let state = setup_state();
    let app = build_router(state);
    let (_, body) = get_html(app, "/").await;

    // Le JS ne doit JAMAIS utiliser innerHTML avec des données dynamiques
    // innerHTML est acceptable uniquement pour des strings statiques (vides)
    // Compter les usages de innerHTML — ne doit pas apparaître avec des variables
    let inner_html_count = body.matches("innerHTML").count();
    // textContent doit être prédominant
    let text_content_count = body.matches("textContent").count();

    assert!(
        text_content_count > inner_html_count,
        "textContent ({}) should be more common than innerHTML ({})",
        text_content_count,
        inner_html_count
    );
}

// ===========================================================================
// 7. Le dashboard utilise SSE ou polling pour les mises à jour
// ===========================================================================

#[tokio::test]
async fn dashboard_html_has_realtime_updates() {
    let state = setup_state();
    let app = build_router(state);
    let (_, body) = get_html(app, "/").await;

    // Doit avoir soit EventSource (SSE) soit setInterval (polling) pour les mises à jour
    assert!(
        body.contains("EventSource") || body.contains("setInterval"),
        "Should have real-time update mechanism (SSE or polling)"
    );
}
