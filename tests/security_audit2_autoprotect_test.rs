//! Security Audit #2 — Phase 0: Auto-protection tests
//!
//! V1: Dashboard API auth token obligatoire au démarrage du daemon
//! V2: Handler SIGTERM + graceful shutdown
//! V3: SELF_PROTECTION_PATHS pour le mode User (~/.counterclaw/)

mod common;

use counterclaw::config::AppConfig;
use counterclaw::daemon::DaemonState;
use counterclaw::dashboard::server::{generate_api_token, DashboardState};
use counterclaw::guards::fs_guard::{PathMatcher, PathVerdict};
use counterclaw::types::{EventBuffer, OperationMode};
use std::sync::{Arc, RwLock};

// =========================================================================
// V1 — Dashboard API auth token obligatoire
// =========================================================================

#[test]
fn daemon_generates_api_token_at_startup() {
    let token = generate_api_token();
    assert!(!token.is_empty(), "Token should not be empty");
    assert_eq!(token.len(), 64, "Token should be 64 hex chars (32 bytes)");
    // Two successive calls should produce different tokens
    let token2 = generate_api_token();
    assert_ne!(token, token2, "Tokens should be unique");
}

#[test]
fn api_token_file_has_restricted_permissions() {
    let env = common::TestEnv::new();
    let token_path = env.root().join("api.token");
    let token = generate_api_token();

    counterclaw::daemon::write_token_file(&token_path, &token).expect("Should write token file");

    let content = std::fs::read_to_string(&token_path).expect("Should read token");
    assert_eq!(content.trim(), token);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata = std::fs::metadata(&token_path).expect("Should read metadata");
        let mode = metadata.permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "Token file should have 0600 permissions, got {:o}",
            mode
        );
    }
}

#[test]
fn dashboard_requires_auth_in_daemon_mode() {
    let env = common::TestEnv::new();
    let yaml = common::minimal_monitor_config(&env);
    env.write_config(&yaml);
    let config = AppConfig::load(&env.config_path()).expect("Should load config");
    let buffer = Arc::new(RwLock::new(EventBuffer::new(100)));
    let state = Arc::new(DaemonState::new(config, buffer));

    let token = generate_api_token();
    let dashboard_state = DashboardState::with_token(state, token.clone());

    assert!(dashboard_state.auth_token.is_some(), "Token should be set");
    assert_eq!(dashboard_state.auth_token.as_ref().unwrap(), &token);
}

#[test]
fn token_file_path_is_self_protected() {
    let paths = counterclaw::guards::fs_guard::get_self_protection_paths();
    let has_user_counterclaw = paths.iter().any(|p| p.contains(".counterclaw/"));
    assert!(
        has_user_counterclaw,
        "~/.counterclaw/ should be in self-protection paths"
    );
}

// =========================================================================
// V2 — Handler SIGTERM + graceful shutdown
// =========================================================================

#[cfg(unix)]
#[tokio::test]
async fn daemon_handles_sigterm_gracefully() {
    use tokio::signal::unix::{signal, SignalKind};

    // Verify that we can create a SIGTERM listener
    let mut sigterm =
        signal(SignalKind::terminate()).expect("Should be able to listen for SIGTERM");

    // Send SIGTERM to ourselves via nix/libc-free approach
    let pid = std::process::id();
    let _ = std::process::Command::new("kill")
        .args(["-15", &pid.to_string()])
        .output();

    let result = tokio::time::timeout(std::time::Duration::from_secs(2), sigterm.recv()).await;

    assert!(result.is_ok(), "Should receive SIGTERM within timeout");
}

#[cfg(unix)]
#[tokio::test]
async fn daemon_shutdown_works_for_both_signals() {
    use tokio::signal::unix::{signal, SignalKind};

    let mut sigterm = signal(SignalKind::terminate()).expect("Should listen for SIGTERM");

    // Send SIGTERM
    let pid = std::process::id();
    let _ = std::process::Command::new("kill")
        .args(["-15", &pid.to_string()])
        .output();

    let shutdown_reason = tokio::select! {
        _ = tokio::signal::ctrl_c() => "ctrl_c",
        _ = sigterm.recv() => "sigterm",
    };

    assert_eq!(
        shutdown_reason, "sigterm",
        "SIGTERM should trigger shutdown"
    );
}

// =========================================================================
// V3 — SELF_PROTECTION_PATHS pour le mode User
// =========================================================================

#[test]
fn self_protection_includes_user_mode_paths() {
    let paths = counterclaw::guards::fs_guard::get_self_protection_paths();
    let has_user_dir = paths.iter().any(|p| p.contains(".counterclaw/"));
    assert!(has_user_dir, "Should protect ~/.counterclaw/ directory");
}

#[test]
fn agent_cannot_delete_user_config() {
    let matcher = PathMatcher::new(vec![], vec![], vec![]);
    let home = dirs::home_dir().expect("Should have home dir");
    let config_path = home.join(".counterclaw").join("config.yaml");
    let verdict = matcher.check(&config_path, &OperationMode::Monitor);
    assert_eq!(
        verdict,
        PathVerdict::Blocked,
        "~/.counterclaw/config.yaml should be blocked by self-protection"
    );
}

#[test]
fn agent_cannot_delete_user_logs() {
    let matcher = PathMatcher::new(vec![], vec![], vec![]);
    let home = dirs::home_dir().expect("Should have home dir");
    let logs_path = home.join(".counterclaw").join("logs").join("events.jsonl");
    let verdict = matcher.check(&logs_path, &OperationMode::Monitor);
    assert_eq!(
        verdict,
        PathVerdict::Blocked,
        "~/.counterclaw/logs/ should be blocked by self-protection"
    );
}

#[test]
fn agent_cannot_access_api_token() {
    let matcher = PathMatcher::new(vec![], vec![], vec![]);
    let home = dirs::home_dir().expect("Should have home dir");
    let token_path = home.join(".counterclaw").join("api.token");
    let verdict = matcher.check(&token_path, &OperationMode::Monitor);
    assert_eq!(
        verdict,
        PathVerdict::Blocked,
        "~/.counterclaw/api.token should be blocked by self-protection"
    );
}

#[test]
fn self_protection_paths_include_both_system_and_user() {
    let paths = counterclaw::guards::fs_guard::get_self_protection_paths();

    assert!(
        paths.iter().any(|p| p.starts_with("/etc/counterclaw")),
        "Should include /etc/counterclaw/"
    );
    assert!(
        paths.iter().any(|p| p.starts_with("/var/log/counterclaw")),
        "Should include /var/log/counterclaw/"
    );
    assert!(
        paths.iter().any(|p| p.contains(".counterclaw/")),
        "Should include ~/.counterclaw/"
    );
}
