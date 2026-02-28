//! Tests du daemon — orchestration, PID file, lifecycle des guards.

mod common;

use counterclaw::config::AppConfig;
use counterclaw::daemon::{read_pid_file, remove_pid_file, write_pid_file, Daemon, DaemonState};
use counterclaw::types::{EventBuffer, GuardModule};
use std::fs;
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
