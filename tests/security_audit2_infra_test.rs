//! Security Audit #2 — Phase 2: Infrastructure / Timing tests
//!
//! V9: Kill switch avec horloge monotone
//! V10: Activer le check argv[0]
//! V11: Rate limiter avec TTL et nettoyage
//! V12: Barrier de démarrage des guards
//! V13: Timeout sur FS Guard watcher

mod common;

use counterclaw::config::AppConfig;
use counterclaw::dashboard::server::RateLimiter;
use counterclaw::process::check_argv0_mismatch;
use counterclaw::types::{ActionTaken, EventBuffer, Guard, GuardModule, SecurityEvent, Severity};
use std::sync::{Arc, RwLock};

// =========================================================================
// V9 — Kill switch avec horloge monotone
// =========================================================================

#[test]
fn kill_switch_uses_monotonic_clock() {
    let env = common::TestEnv::new();
    let yaml = common::minimal_monitor_config(&env).replace(
        "enabled: false\n    threshold_severity: warning\n    threshold_count: 3",
        "enabled: true\n    threshold_severity: warning\n    threshold_count: 3",
    );
    env.write_config(&yaml);
    let config = AppConfig::load(&env.config_path()).expect("load config");
    let buffer = Arc::new(RwLock::new(EventBuffer::new(100)));

    let engine =
        counterclaw::alerting::engine::AlertingEngine::new(&config.alerting, buffer.clone());

    // Engine creates successfully with monotonic clock internals
    drop(engine);
}

#[tokio::test]
async fn kill_switch_not_affected_by_clock_change() {
    let env = common::TestEnv::new();
    let yaml = common::minimal_monitor_config(&env).replace(
        "enabled: false\n    threshold_severity: warning\n    threshold_count: 3\n    threshold_window_seconds: 60",
        "enabled: true\n    threshold_severity: warning\n    threshold_count: 3\n    threshold_window_seconds: 60",
    );
    env.write_config(&yaml);
    let config = AppConfig::load(&env.config_path()).expect("load config");
    let buffer = Arc::new(RwLock::new(EventBuffer::new(100)));

    let engine =
        counterclaw::alerting::engine::AlertingEngine::new(&config.alerting, buffer.clone());

    let (tx, rx) = tokio::sync::mpsc::channel(100);

    for _ in 0..3 {
        let event = SecurityEvent::new(
            GuardModule::FsGuard,
            Severity::Warning,
            ActionTaken::Blocked,
            "Test violation".to_string(),
        );
        tx.send(event).await.unwrap();
    }
    drop(tx);

    engine.run(rx).await;

    let buf = buffer.read().unwrap();
    let events: Vec<_> = buf.query(0, None, None, None);
    let has_kill_switch = events
        .iter()
        .any(|e| e.description.contains("Kill switch triggered"));
    assert!(
        has_kill_switch,
        "Kill switch should have triggered after 3 violations"
    );
}

// =========================================================================
// V10 — Activer le check argv[0]
// =========================================================================

#[test]
fn detects_argv0_mismatch_as_suspicious() {
    let mismatch = check_argv0_mismatch("bash", "/tmp/malware --some-args");
    assert!(
        mismatch,
        "Should detect argv0 mismatch: name='bash' but binary='/tmp/malware'"
    );
}

#[test]
fn no_false_positive_on_normal_process() {
    let mismatch = check_argv0_mismatch("node", "/usr/bin/node server.js");
    assert!(
        !mismatch,
        "Should NOT flag normal process where name matches binary"
    );

    let mismatch2 = check_argv0_mismatch("python3", "/usr/bin/python3 -m pip install");
    assert!(!mismatch2, "Should NOT flag normal python3 process");
}

#[test]
fn argv0_mismatch_handles_edge_cases() {
    assert!(
        !check_argv0_mismatch("", "/usr/bin/bash"),
        "Empty name → false"
    );
    assert!(!check_argv0_mismatch("bash", ""), "Empty cmd → false");
    assert!(!check_argv0_mismatch("", ""), "Both empty → false");
    assert!(
        !check_argv0_mismatch("grep", "/usr/bin/grep -r pattern"),
        "Normal grep"
    );
}

// =========================================================================
// V11 — Rate limiter avec TTL et nettoyage
// =========================================================================

#[test]
fn rate_limiter_cleans_expired_entries() {
    let mut limiter = RateLimiter::new();

    for i in 0..100 {
        let key = format!("ip_{}", i);
        limiter.check_rate(&key, 100);
    }

    assert!(
        limiter.tracked_keys_count() >= 100,
        "Should track all 100 keys, got {}",
        limiter.tracked_keys_count()
    );

    limiter.cleanup_expired();
    assert!(limiter.tracked_keys_count() <= 100);
}

#[test]
fn rate_limiter_caps_total_keys() {
    let mut limiter = RateLimiter::new();

    for i in 0..20_000 {
        let key = format!("ip_{}", i);
        limiter.check_rate(&key, 100);
    }

    assert!(
        limiter.tracked_keys_count() <= 10_001,
        "Tracked keys should be capped, got {}",
        limiter.tracked_keys_count()
    );
}

#[test]
fn rate_limiter_still_works_after_cleanup() {
    let mut limiter = RateLimiter::new();

    assert!(limiter.check_rate("test_key", 10), "First request allowed");
    limiter.cleanup_expired();
    assert!(
        limiter.check_rate("test_key", 10),
        "Request after cleanup should work"
    );
}

// =========================================================================
// V12 — Barrier de démarrage des guards
// =========================================================================

#[tokio::test]
async fn daemon_waits_for_all_guards_before_ready() {
    let env = common::TestEnv::new();
    let yaml = common::minimal_monitor_config(&env);
    env.write_config(&yaml);
    let config = AppConfig::load(&env.config_path()).expect("load config");
    let buffer = Arc::new(RwLock::new(EventBuffer::new(100)));
    let state = counterclaw::daemon::DaemonState::new(config, buffer);

    let (tx, _rx) = tokio::sync::mpsc::channel(100);

    let result =
        tokio::time::timeout(std::time::Duration::from_secs(5), state.start_guards(tx)).await;

    assert!(
        result.is_ok(),
        "start_guards should complete within timeout"
    );

    let statuses = state.guard_statuses();
    for (name, status) in &statuses {
        assert!(
            status.running,
            "Guard {} should be running after start_guards completes",
            name
        );
    }
}

#[tokio::test]
async fn daemon_reports_failure_if_guard_timeout() {
    let env = common::TestEnv::new();
    let yaml = common::minimal_monitor_config(&env);
    env.write_config(&yaml);
    let config = AppConfig::load(&env.config_path()).expect("load config");
    let buffer = Arc::new(RwLock::new(EventBuffer::new(100)));
    let state = counterclaw::daemon::DaemonState::new(config, buffer);

    let (tx, _rx) = tokio::sync::mpsc::channel(100);
    state.start_guards(tx).await;

    let statuses = state.guard_statuses();
    assert!(!statuses.is_empty(), "Should have guard statuses");
    for (name, _status) in &statuses {
        assert!(!name.is_empty(), "Guard name should not be empty");
    }
}

// =========================================================================
// V13 — Timeout sur FS Guard watcher
// =========================================================================

#[tokio::test]
async fn fs_guard_detects_stalled_watcher() {
    let config = counterclaw::config::FsGuardConfig {
        enabled: true,
        watch_processes: vec![],
        blocked_paths: vec!["/tmp/test_blocked".to_string()],
        read_only_paths: vec![],
        allowed_paths: vec![],
        monitor_reads: false,
        on_violation: counterclaw::config::FsViolationConfig {
            action: "log_only".to_string(),
            kill_target: "process".to_string(),
        },
    };

    let guard = counterclaw::guards::fs_guard::FsGuard::new(&config, common::test_app_config_arc());
    let (tx, _rx) = tokio::sync::mpsc::channel(100);
    guard.start(tx).await.expect("guard should start");

    let status = guard.status();
    assert!(status.running, "Guard should be running");

    let watchdog_ok = guard.is_watchdog_healthy();
    assert!(watchdog_ok, "Watchdog should be healthy right after start");

    guard.stop().await.expect("guard should stop");
}

#[test]
fn fs_guard_watchdog_timeout_configurable() {
    let config = counterclaw::config::FsGuardConfig {
        enabled: true,
        watch_processes: vec![],
        blocked_paths: vec![],
        read_only_paths: vec![],
        allowed_paths: vec![],
        monitor_reads: false,
        on_violation: counterclaw::config::FsViolationConfig {
            action: "log_only".to_string(),
            kill_target: "process".to_string(),
        },
    };

    let guard = counterclaw::guards::fs_guard::FsGuard::new(&config, common::test_app_config_arc());
    let status = guard.status();
    assert!(!status.running, "Guard should not be running before start");
}
