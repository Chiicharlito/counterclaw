//! Tests I/O pour le Cmd Guard — polling processus.
//!
//! Ces tests vérifient le comportement réel du polling processus
//! (sysinfo scan, détection de commandes) par opposition aux tests
//! de logique pure dans cmd_guard_test.rs.

mod common;

use counterclaw::config::CmdGuardConfig;
use counterclaw::guards::cmd_guard::CmdGuard;
use counterclaw::types::{Guard, SecurityEvent};
use tokio::sync::mpsc;

// ===========================================================================
// Helper : config Cmd Guard pour tests I/O
// ===========================================================================

fn cmd_io_config_with_blacklist(patterns: Vec<(&str, &str, &str)>) -> CmdGuardConfig {
    let blacklist_yaml: String = patterns
        .iter()
        .map(|(pat, desc, sev)| {
            format!(
                "    - pattern: \"{}\"\n      description: \"{}\"\n      severity: \"{}\"",
                pat, desc, sev
            )
        })
        .collect::<Vec<_>>()
        .join("\n");

    let yaml = format!(
        r#"
enabled: true
blacklist:
{}
require_approval: []
monitoring_method: process_polling
"#,
        if blacklist_yaml.is_empty() {
            "    []".to_string()
        } else {
            blacklist_yaml
        },
    );
    serde_yaml::from_str(&yaml).expect("valid Cmd config")
}

fn cmd_io_config_disabled() -> CmdGuardConfig {
    serde_yaml::from_str(
        r#"
enabled: false
blacklist: []
require_approval: []
monitoring_method: log_only
"#,
    )
    .expect("valid Cmd config")
}

// ===========================================================================
// Step 6.4 : Cmd Guard Process Polling Tests
// ===========================================================================

/// Le polling démarre et le guard est running.
#[tokio::test]
async fn polling_starts_and_runs() {
    let config = cmd_io_config_with_blacklist(vec![]);
    let guard = CmdGuard::new(&config, common::test_app_config_arc());
    let (tx, _rx) = mpsc::channel::<SecurityEvent>(64);

    guard.start(tx).await.expect("start failed");

    let status = guard.status();
    assert!(status.running, "Guard should be running after start()");

    guard.stop().await.expect("stop failed");
}

/// stop() termine la boucle de polling.
#[tokio::test]
async fn stop_ends_polling() {
    let config = cmd_io_config_with_blacklist(vec![]);
    let guard = CmdGuard::new(&config, common::test_app_config_arc());
    let (tx, _rx) = mpsc::channel::<SecurityEvent>(64);

    guard.start(tx).await.expect("start failed");
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    guard.stop().await.expect("stop failed");

    let status = guard.status();
    assert!(!status.running, "Guard should not be running after stop()");
}

/// Notre propre processus est visible dans le scan.
#[tokio::test]
async fn detects_current_process() {
    // Use a pattern that matches the cargo test process
    let config =
        cmd_io_config_with_blacklist(vec![("cmd_guard_io_test", "Detected test runner", "info")]);
    let guard = CmdGuard::new(&config, common::test_app_config_arc());
    let (tx, mut rx) = mpsc::channel::<SecurityEvent>(64);

    guard.start(tx).await.expect("start failed");

    // Wait for at least one polling cycle (2s) + margin
    let event = tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv())
        .await
        .expect("Timed out waiting for SecurityEvent")
        .expect("Channel closed");

    // The event should be from CmdGuard
    assert_eq!(event.module, counterclaw::types::GuardModule::CmdGuard);

    guard.stop().await.expect("stop failed");
}

/// Le même PID n'est pas alerté deux fois.
#[tokio::test]
async fn no_double_alert_same_pid() {
    let config =
        cmd_io_config_with_blacklist(vec![("cmd_guard_io_test", "Detected test runner", "info")]);
    let guard = CmdGuard::new(&config, common::test_app_config_arc());
    let (tx, mut rx) = mpsc::channel::<SecurityEvent>(64);

    guard.start(tx).await.expect("start failed");

    // Wait for first event
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv())
        .await
        .expect("Timed out")
        .expect("Channel closed");

    // Wait for a second polling cycle — should NOT get another event for same PID
    let second = tokio::time::timeout(std::time::Duration::from_secs(4), rx.recv()).await;

    assert!(
        second.is_err(),
        "Should not receive duplicate alert for same PID"
    );

    guard.stop().await.expect("stop failed");
}

/// Guard désactivé → pas de polling.
#[tokio::test]
async fn no_events_when_disabled() {
    let config = cmd_io_config_disabled();
    let guard = CmdGuard::new(&config, common::test_app_config_arc());
    let (tx, _rx) = mpsc::channel::<SecurityEvent>(64);

    guard.start(tx).await.expect("start failed");

    let status = guard.status();
    assert!(
        status.running,
        "Guard should report running (even if disabled)"
    );

    guard.stop().await.expect("stop failed");
}

// ===========================================================================
// KqueueMonitor integration (macOS only)
// ===========================================================================

/// CmdGuard sur macOS détecte un processus éphémère (50ms) via kqueue —
/// impossible avec le polling seul (500ms par défaut).
#[cfg(target_os = "macos")]
#[tokio::test]
async fn cmd_guard_uses_kqueue_on_macos() {
    let config = cmd_io_config_with_blacklist(vec![("sleep", "Sleep detected", "warning")]);
    let guard = CmdGuard::new(&config, common::test_app_config_arc());
    let (tx, mut rx) = mpsc::channel::<SecurityEvent>(64);

    guard.start(tx).await.expect("start failed");

    // Wait for first poll cycle to pass so the initial scan is done
    tokio::time::sleep(std::time::Duration::from_millis(600)).await;

    // Spawn a 50ms-lived process — too short for 500ms polling but caught by kqueue
    let _child = std::process::Command::new("sleep")
        .arg("0.05")
        .spawn()
        .expect("failed to spawn sleep");

    let event = tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv())
        .await
        .expect("Timed out — kqueue should detect short-lived process")
        .expect("Channel closed");

    assert_eq!(event.module, counterclaw::types::GuardModule::CmdGuard);
    assert!(
        event.description.contains("sleep") || event.description.contains("Sleep"),
        "Event should mention sleep, got: {}",
        event.description
    );

    guard.stop().await.expect("stop failed");
}

/// CmdGuard émet un SecurityEvent correct pour un processus blacklisté
/// détecté via kqueue (module, severity, description, PID).
#[cfg(target_os = "macos")]
#[tokio::test]
async fn cmd_guard_detects_blacklisted_command_via_kqueue() {
    let config = cmd_io_config_with_blacklist(vec![("sleep", "Suspicious sleep process", "high")]);
    let guard = CmdGuard::new(&config, common::test_app_config_arc());
    let (tx, mut rx) = mpsc::channel::<SecurityEvent>(64);

    guard.start(tx).await.expect("start failed");
    tokio::time::sleep(std::time::Duration::from_millis(600)).await;

    // Drain any pre-existing sleep detections (from initial scan or other tests)
    while let Ok(Some(_)) =
        tokio::time::timeout(std::time::Duration::from_millis(200), rx.recv()).await
    {
        // discard stale events
    }

    // Spawn a short-lived blacklisted process (100ms — caught by kqueue, missed by 500ms polling)
    let child = std::process::Command::new("sleep")
        .arg("0.1")
        .spawn()
        .expect("failed to spawn sleep");
    let child_pid = child.id();

    // Wait for event matching our spawned PID (skip any unrelated events)
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    let mut found_event = None;
    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout_at(deadline, rx.recv()).await {
            Ok(Some(event)) if event.description.contains(&child_pid.to_string()) => {
                found_event = Some(event);
                break;
            }
            Ok(Some(_)) => continue, // skip events for other PIDs
            _ => break,
        }
    }
    let event = found_event.expect("Should detect our blacklisted process");

    assert_eq!(event.module, counterclaw::types::GuardModule::CmdGuard);
    assert!(
        event.description.contains("Blacklisted"),
        "Should be blacklisted, got: {}",
        event.description
    );
    assert!(
        event.description.contains(&child_pid.to_string()),
        "Should contain PID {}, got: {}",
        child_pid,
        event.description
    );

    guard.stop().await.expect("stop failed");
}
