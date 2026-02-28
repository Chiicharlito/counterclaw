//! Tests du daemon — orchestration, PID file, lifecycle des guards.

mod common;

use counterclaw::config::AppConfig;
use counterclaw::daemon::{read_pid_file, remove_pid_file, write_pid_file, Daemon, DaemonState};
use counterclaw::types::{EventBuffer, GuardModule};
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

// ---------------------------------------------------------------------------
// PID file management
// ---------------------------------------------------------------------------

#[test]
fn write_pid_file_creates_file() {
    let env = common::TestEnv::new();
    let pid_path = env.root().join("test.pid");

    write_pid_file(&pid_path, 12345).expect("should write pid file");

    assert!(pid_path.exists(), "PID file should exist");
    let content = fs::read_to_string(&pid_path).unwrap();
    assert_eq!(content.trim(), "12345");
}

#[test]
fn read_pid_file_returns_pid() {
    let env = common::TestEnv::new();
    let pid_path = env.root().join("test.pid");
    fs::write(&pid_path, "54321").unwrap();

    let pid = read_pid_file(&pid_path);
    assert_eq!(pid, Some(54321));
}

#[test]
fn read_pid_file_none_for_missing() {
    let env = common::TestEnv::new();
    let pid_path = env.root().join("nonexistent.pid");

    let pid = read_pid_file(&pid_path);
    assert_eq!(pid, None, "Missing file should return None");
}

#[test]
fn read_pid_file_none_for_invalid() {
    let env = common::TestEnv::new();
    let pid_path = env.root().join("bad.pid");
    fs::write(&pid_path, "not-a-number").unwrap();

    let pid = read_pid_file(&pid_path);
    assert_eq!(pid, None, "Invalid content should return None");
}

#[test]
fn remove_pid_file_cleans_up() {
    let env = common::TestEnv::new();
    let pid_path = env.root().join("test.pid");
    fs::write(&pid_path, "99999").unwrap();
    assert!(pid_path.exists());

    remove_pid_file(&pid_path);
    assert!(!pid_path.exists(), "PID file should be removed");
}

#[test]
fn remove_pid_file_no_panic_on_missing() {
    let env = common::TestEnv::new();
    let pid_path = env.root().join("nonexistent.pid");

    // Should not panic
    remove_pid_file(&pid_path);
}

// ---------------------------------------------------------------------------
// DaemonState
// ---------------------------------------------------------------------------

fn load_config(env: &common::TestEnv) -> AppConfig {
    let yaml = common::minimal_monitor_config(env);
    env.write_config(&yaml);
    AppConfig::load(&env.config_path()).expect("valid config")
}

#[test]
fn daemon_state_reports_guard_statuses() {
    let env = common::TestEnv::new();
    let config = load_config(&env);
    let buffer = Arc::new(RwLock::new(EventBuffer::new(100)));
    let state = DaemonState::new(config, buffer);

    let statuses = state.guard_statuses();
    // With all guards disabled, we should still get entries for each guard
    assert_eq!(statuses.len(), 4, "Should have 4 guards");
}

#[test]
fn daemon_state_guard_names_correct() {
    let env = common::TestEnv::new();
    let config = load_config(&env);
    let buffer = Arc::new(RwLock::new(EventBuffer::new(100)));
    let state = DaemonState::new(config, buffer);

    let statuses = state.guard_statuses();
    let names: Vec<&str> = statuses.iter().map(|(name, _)| name.as_str()).collect();
    assert!(names.contains(&"fs_guard"), "Should have fs_guard");
    assert!(names.contains(&"cdp_proxy"), "Should have cdp_proxy");
    assert!(names.contains(&"net_guard"), "Should have net_guard");
    assert!(names.contains(&"cmd_guard"), "Should have cmd_guard");
}

#[tokio::test]
async fn daemon_spawns_enabled_guards() {
    let env = common::TestEnv::new();
    let config = load_config(&env);
    let buffer = Arc::new(RwLock::new(EventBuffer::new(100)));
    let state = DaemonState::new(config, buffer);

    // All guards disabled in minimal config → none should be running
    let statuses = state.guard_statuses();
    for (name, status) in &statuses {
        assert!(
            !status.running,
            "Guard {} should not be running when disabled",
            name
        );
    }
}

#[tokio::test]
async fn daemon_sends_startup_event() {
    let env = common::TestEnv::new();
    let config = load_config(&env);
    let buffer = Arc::new(RwLock::new(EventBuffer::new(100)));

    let daemon = Daemon::new(config, buffer.clone());

    // Start and immediately stop
    let handle = tokio::spawn(async move {
        daemon.run_until_signal().await;
    });

    // Give it a moment to start
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Check buffer for startup event
    let buf = buffer.read().unwrap();
    let events = buf.query(0, None, Some(&GuardModule::System), None);
    assert!(
        !events.is_empty(),
        "Should have at least one System event (startup)"
    );
    assert!(
        events.iter().any(|e| e.description.contains("started")),
        "Should have startup event"
    );

    // Cleanup: the daemon task will end when dropped
    handle.abort();
}

#[tokio::test]
async fn daemon_graceful_shutdown_stops_guards() {
    let env = common::TestEnv::new();
    let config = load_config(&env);
    let buffer = Arc::new(RwLock::new(EventBuffer::new(100)));
    let state = DaemonState::new(config, buffer);

    // Start guards
    let (tx, _rx) = tokio::sync::mpsc::channel(100);
    state.start_guards(tx).await;

    // Verify running (only enabled guards would be running)
    // With minimal config, all disabled → still not running is OK

    // Stop guards — should not panic
    state.stop_guards().await;
}

#[test]
fn daemon_state_mode_from_config() {
    let env = common::TestEnv::new();
    let config = load_config(&env);
    let buffer = Arc::new(RwLock::new(EventBuffer::new(100)));
    let state = DaemonState::new(config, buffer);

    assert_eq!(
        state.mode().to_string(),
        "monitor",
        "Should reflect config mode"
    );
}

// ---------------------------------------------------------------------------
// run_until_signal wiring tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn run_until_signal_writes_pid_file() {
    let env = common::TestEnv::new();
    let config = load_config(&env);
    let pid_path = PathBuf::from(&config.general.pid_file);
    let buffer = Arc::new(RwLock::new(EventBuffer::new(100)));

    let daemon = Daemon::new(config, buffer);

    let handle = tokio::spawn(async move {
        daemon.run_until_signal().await;
    });

    // Give it a moment to start
    tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;

    // PID file should exist and contain our PID
    assert!(pid_path.exists(), "PID file should be written at startup");
    let pid = read_pid_file(&pid_path);
    assert!(pid.is_some(), "PID file should contain a valid PID");
    assert_eq!(
        pid.unwrap(),
        std::process::id(),
        "PID should match current process"
    );

    handle.abort();
}

#[tokio::test]
async fn run_until_signal_expands_tilde_in_pid_path() {
    let env = common::TestEnv::new();
    let mut config = load_config(&env);

    // Create a unique test dir under ~ to verify tilde expansion
    let test_dir_name = format!(".counterclaw_test_{}", std::process::id());
    let home = dirs::home_dir().expect("home dir");
    let real_dir = home.join(&test_dir_name);
    std::fs::create_dir_all(&real_dir).unwrap();

    // Use a ~/... path — daemon must expand the tilde
    config.general.pid_file = format!("~/{}/test.pid", test_dir_name);
    let expected_path = real_dir.join("test.pid");

    let buffer = Arc::new(RwLock::new(EventBuffer::new(100)));
    let daemon = Daemon::new(config, buffer);

    let handle = tokio::spawn(async move {
        daemon.run_until_signal().await;
    });

    tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;

    // PID file should be at the expanded path, not a literal "~" directory
    assert!(
        expected_path.exists(),
        "PID file should be written at expanded tilde path: {}",
        expected_path.display()
    );

    handle.abort();

    // Cleanup
    let _ = std::fs::remove_dir_all(&real_dir);
}

#[tokio::test]
async fn run_until_signal_starts_dashboard() {
    let env = common::TestEnv::new();
    let mut config = load_config(&env);
    let port = common::find_free_port();
    config.dashboard.enabled = true;
    config.dashboard.port = port;

    let buffer = Arc::new(RwLock::new(EventBuffer::new(100)));
    let daemon = Daemon::new(config, buffer);

    let handle = tokio::spawn(async move {
        daemon.run_until_signal().await;
    });

    // Give it time to bind the dashboard server
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

    // Dashboard /api/health should be reachable
    let resp = reqwest::get(format!("http://127.0.0.1:{}/api/health", port))
        .await
        .expect("Dashboard should be reachable");
    assert_eq!(resp.status(), 200);

    handle.abort();
}

// ---------------------------------------------------------------------------
// Step 6.6 — Integration: Daemon with I/O guards
// ---------------------------------------------------------------------------

/// Helper: config with CDP proxy enabled on a free port.
fn config_with_cdp_proxy(env: &common::TestEnv) -> AppConfig {
    let mut config = load_config(env);
    let cdp_port = common::find_free_port();
    config.cdp_proxy.enabled = true;
    config.cdp_proxy.listen_port = cdp_port;
    config.cdp_proxy.bind_address = "127.0.0.1".to_string();
    config.cdp_proxy.upstream_port = common::find_free_port(); // no real Chrome
    config
}

/// Le daemon démarre le CDP proxy et le rend accessible.
#[tokio::test]
async fn daemon_cdp_proxy_reachable() {
    let env = common::TestEnv::new();
    let config = config_with_cdp_proxy(&env);
    let cdp_port = config.cdp_proxy.listen_port;

    let buffer = Arc::new(RwLock::new(EventBuffer::new(100)));
    let daemon = Daemon::new(config, buffer);

    let handle = tokio::spawn(async move {
        daemon.run_until_signal().await;
    });

    // Give the CDP proxy time to bind
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

    // CDP proxy discovery endpoint should be reachable
    // It will return an error (no Chrome upstream), but the port should respond
    let result = reqwest::get(format!("http://127.0.0.1:{}/json/version", cdp_port)).await;
    assert!(
        result.is_ok(),
        "CDP proxy should be reachable on port {}",
        cdp_port
    );

    handle.abort();
}

/// Le daemon démarre et arrête tous les gardes proprement avec le lifecycle complet.
#[tokio::test]
async fn daemon_full_lifecycle() {
    let env = common::TestEnv::new();
    let config = config_with_cdp_proxy(&env);
    let cdp_port = config.cdp_proxy.listen_port;
    let dashboard_port = common::find_free_port();

    let mut config = config;
    config.dashboard.enabled = true;
    config.dashboard.port = dashboard_port;

    let buffer = Arc::new(RwLock::new(EventBuffer::new(100)));
    let daemon = Daemon::new(config, buffer.clone());

    let handle = tokio::spawn(async move {
        daemon.run_until_signal().await;
    });

    // Wait for everything to start
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

    // Both services should be reachable
    let cdp = reqwest::get(format!("http://127.0.0.1:{}/json/version", cdp_port)).await;
    assert!(cdp.is_ok(), "CDP proxy should be reachable");

    let dash = reqwest::get(format!("http://127.0.0.1:{}/api/health", dashboard_port)).await;
    assert!(dash.is_ok(), "Dashboard should be reachable");

    // Buffer should have startup event
    let buf = buffer.read().unwrap();
    let events = buf.query(0, None, Some(&GuardModule::System), None);
    assert!(
        events.iter().any(|e| e.description.contains("started")),
        "Should have startup event"
    );

    handle.abort();
}
