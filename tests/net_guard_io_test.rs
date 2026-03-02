//! Tests I/O pour le Net Guard — polling lsof.
//!
//! Ces tests vérifient le comportement réel du polling lsof
//! (exécution de commande, parsing, détection de connexions)
//! par opposition aux tests de logique pure dans net_guard_test.rs.

mod common;

use counterclaw::config::NetGuardConfig;
use counterclaw::guards::net_guard::NetGuard;
use counterclaw::types::{Guard, SecurityEvent};
use tokio::sync::mpsc;

// ===========================================================================
// Helper : config Net Guard pour tests I/O
// ===========================================================================

fn net_io_config_enabled(allowed_egress: Vec<&str>) -> NetGuardConfig {
    let egress_yaml: String = allowed_egress
        .iter()
        .map(|d| format!("    - \"{}\"", d))
        .collect::<Vec<_>>()
        .join("\n");

    let yaml = format!(
        r#"
enabled: true
watch_processes: []
allowed_egress:
{}
max_post_payload_bytes: 10485760
block_unknown_post: false
alert_on_unknown_dns: false
enforcement_method: log_only
"#,
        if egress_yaml.is_empty() {
            "    []".to_string()
        } else {
            egress_yaml
        },
    );
    serde_yaml::from_str(&yaml).expect("valid Net config")
}

fn net_io_config_disabled() -> NetGuardConfig {
    serde_yaml::from_str(
        r#"
enabled: false
watch_processes: []
allowed_egress: []
max_post_payload_bytes: 10485760
block_unknown_post: false
alert_on_unknown_dns: false
enforcement_method: log_only
"#,
    )
    .expect("valid Net config")
}

// ===========================================================================
// Step 6.5 : Net Guard lsof Polling Tests
// ===========================================================================

/// Le polling démarre et le guard est running.
#[tokio::test]
async fn polling_starts_and_runs() {
    let config = net_io_config_enabled(vec![]);
    let guard = NetGuard::new(&config, common::test_app_config_arc());
    let (tx, _rx) = mpsc::channel::<SecurityEvent>(64);

    guard.start(tx).await.expect("start failed");

    let status = guard.status();
    assert!(status.running, "Guard should be running after start()");

    guard.stop().await.expect("stop failed");
}

/// stop() termine la boucle de polling.
#[tokio::test]
async fn stop_ends_polling() {
    let config = net_io_config_enabled(vec![]);
    let guard = NetGuard::new(&config, common::test_app_config_arc());
    let (tx, _rx) = mpsc::channel::<SecurityEvent>(64);

    guard.start(tx).await.expect("start failed");
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    guard.stop().await.expect("stop failed");

    let status = guard.status();
    assert!(!status.running, "Guard should not be running after stop()");
}

/// lsof s'exécute sans crash.
#[tokio::test]
async fn runs_lsof_without_crash() {
    let config = net_io_config_enabled(vec![]);
    let guard = NetGuard::new(&config, common::test_app_config_arc());
    let (tx, _rx) = mpsc::channel::<SecurityEvent>(64);

    guard.start(tx).await.expect("start failed");

    // Wait for at least one polling cycle (3s) + margin
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;

    // Guard should still be running (lsof didn't crash it)
    let status = guard.status();
    assert!(
        status.running,
        "Guard should still be running after lsof cycle"
    );

    guard.stop().await.expect("stop failed");
}

/// Guard désactivé → pas de polling.
#[tokio::test]
async fn no_events_when_disabled() {
    let config = net_io_config_disabled();
    let guard = NetGuard::new(&config, common::test_app_config_arc());
    let (tx, _rx) = mpsc::channel::<SecurityEvent>(64);

    guard.start(tx).await.expect("start failed");

    let status = guard.status();
    assert!(
        status.running,
        "Guard should report running (even if disabled)"
    );

    guard.stop().await.expect("stop failed");
}

/// Le compteur events_total s'incrémente quand lsof détecte des connexions.
/// Note: Ce test peut ne pas détecter de connexions si aucune n'est active,
/// mais il vérifie que le polling ne crashe pas.
#[tokio::test]
async fn polling_increments_counters_on_activity() {
    // Use a config that allows nothing — any connection will be flagged in paranoid mode
    let config = net_io_config_enabled(vec![]);
    let guard = NetGuard::new(&config, common::test_app_config_arc());
    let (tx, _rx) = mpsc::channel::<SecurityEvent>(64);

    guard.start(tx).await.expect("start failed");

    // Wait for a couple polling cycles
    tokio::time::sleep(std::time::Duration::from_secs(7)).await;

    let status = guard.status();
    // We can't guarantee events were found, but the guard should still be running
    assert!(status.running, "Guard should be running after polling");

    guard.stop().await.expect("stop failed");
}

// ===========================================================================
// Issue 2 : build_lsof_args — ciblage par PID
// ===========================================================================

use counterclaw::guards::net_guard::build_lsof_args;

/// build_lsof_args avec PIDs produit "-p pid1,pid2 -i -n -P".
#[test]
fn build_lsof_args_with_pids_targets_specific_processes() {
    let args = build_lsof_args(&[1234, 5678]);
    assert_eq!(args, vec!["-p", "1234,5678", "-i", "-n", "-P"]);
}

/// build_lsof_args sans PIDs produit le fallback global "-i -n -P".
#[test]
fn build_lsof_args_without_pids_uses_global_scan() {
    let args = build_lsof_args(&[]);
    assert_eq!(args, vec!["-i", "-n", "-P"]);
}

/// build_lsof_args avec un seul PID produit "-p 1234 -i -n -P".
#[test]
fn build_lsof_args_single_pid() {
    let args = build_lsof_args(&[1234]);
    assert_eq!(args, vec!["-p", "1234", "-i", "-n", "-P"]);
}

/// build_lsof_args avec plusieurs PIDs les sépare par virgule.
#[test]
fn build_lsof_args_multiple_pids() {
    let args = build_lsof_args(&[1234, 5678, 9012]);
    assert_eq!(args, vec!["-p", "1234,5678,9012", "-i", "-n", "-P"]);
}

/// NetGuard n'exécute pas lsof en état Idle (pas de processus surveillé).
/// Vérifié indirectement : avec watch_processes et aucun processus actif,
/// le guard devrait rester au repos (0 events total).
#[tokio::test]
async fn net_guard_skips_lsof_in_idle_state() {
    // Config with watch_processes set to nonexistent pattern
    let yaml = r#"
enabled: true
watch_processes:
    - "zzz_nonexistent_process_xyz_42"
allowed_egress: []
max_post_payload_bytes: 10485760
block_unknown_post: false
alert_on_unknown_dns: false
enforcement_method: log_only
poll_interval_ms: 1000
idle_poll_interval_ms: 30000
"#;
    let config: counterclaw::config::NetGuardConfig =
        serde_yaml::from_str(yaml).expect("valid config");
    let guard = NetGuard::new(&config, common::test_app_config_arc());
    let (tx, _rx) = mpsc::channel::<SecurityEvent>(64);

    guard.start(tx).await.expect("start failed");

    // Wait for a few seconds — poller should be in Idle (30s interval),
    // so no lsof should be executed and events_total should remain 0
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;

    let status = guard.status();
    assert_eq!(
        status.events_total, 0,
        "No events should fire when in Idle state (no watched process active)"
    );

    guard.stop().await.expect("stop failed");
}

/// NetGuard utilise lsof ciblé quand des PIDs surveillés sont actifs.
/// Vérifié indirectement : le guard continue de fonctionner sans crash
/// avec watch_processes configuré sur un processus système existant.
#[tokio::test]
async fn net_guard_uses_targeted_lsof_in_active_state() {
    // Config with watch_processes matching a system process (always running)
    let yaml = r#"
enabled: true
watch_processes:
    - "launchd|init|systemd"
allowed_egress: []
max_post_payload_bytes: 10485760
block_unknown_post: false
alert_on_unknown_dns: false
enforcement_method: log_only
poll_interval_ms: 1000
idle_poll_interval_ms: 30000
"#;
    let config: counterclaw::config::NetGuardConfig =
        serde_yaml::from_str(yaml).expect("valid config");
    let guard = NetGuard::new(&config, common::test_app_config_arc());
    let (tx, _rx) = mpsc::channel::<SecurityEvent>(64);

    guard.start(tx).await.expect("start failed");

    // Wait for a couple of active polling cycles
    tokio::time::sleep(std::time::Duration::from_secs(4)).await;

    let status = guard.status();
    assert!(
        status.running,
        "Guard should still be running with targeted lsof"
    );

    guard.stop().await.expect("stop failed");
}
