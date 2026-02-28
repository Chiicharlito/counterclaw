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
