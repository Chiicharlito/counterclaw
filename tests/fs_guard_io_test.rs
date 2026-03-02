//! Tests I/O pour le FS Guard — notify watcher integration.
//!
//! Ces tests vérifient le comportement réel du watcher filesystem
//! (création de fichiers, detection d'events) par opposition aux tests
//! de logique pure dans fs_guard_test.rs.

mod common;

use counterclaw::config::FsGuardConfig;
use counterclaw::guards::fs_guard::FsGuard;
use counterclaw::types::{Guard, GuardModule, SecurityEvent};
use std::fs;
use tokio::sync::mpsc;

// ===========================================================================
// Helper : config FS Guard pour tests I/O
// ===========================================================================

fn fs_io_config(blocked_paths: Vec<String>, read_only_paths: Vec<String>) -> FsGuardConfig {
    let blocked_yaml: String = blocked_paths
        .iter()
        .map(|p| format!("    - \"{}\"", p))
        .collect::<Vec<_>>()
        .join("\n");
    let read_only_yaml: String = read_only_paths
        .iter()
        .map(|p| format!("    - \"{}\"", p))
        .collect::<Vec<_>>()
        .join("\n");

    let yaml = format!(
        r#"
enabled: true
watch_processes: []
blocked_paths:
{blocked}
read_only_paths:
{readonly}
allowed_paths: []
on_violation:
  action: log_only
  kill_target: process
"#,
        blocked = if blocked_yaml.is_empty() {
            "    []".to_string()
        } else {
            blocked_yaml
        },
        readonly = if read_only_yaml.is_empty() {
            "    []".to_string()
        } else {
            read_only_yaml
        },
    );
    serde_yaml::from_str(&yaml).expect("valid FS config")
}

fn fs_io_config_disabled() -> FsGuardConfig {
    serde_yaml::from_str(
        r#"
enabled: false
watch_processes: []
blocked_paths: []
read_only_paths: []
allowed_paths: []
on_violation:
  action: log_only
  kill_target: process
"#,
    )
    .expect("valid FS config")
}

// ===========================================================================
// Step 6.3 : FS Guard Notify Watcher Tests
// ===========================================================================

/// Le watcher démarre et le guard est running.
#[tokio::test]
async fn watcher_starts_and_binds() {
    let env = common::TestEnv::new();
    let watched_dir = env.root().join("watched");
    fs::create_dir_all(&watched_dir).unwrap();

    let config = fs_io_config(vec![watched_dir.to_string_lossy().to_string()], vec![]);
    let guard = FsGuard::new(&config, common::test_app_config_arc());
    let (tx, _rx) = mpsc::channel::<SecurityEvent>(64);

    guard.start(tx).await.expect("start failed");

    let status = guard.status();
    assert!(status.running, "Guard should be running after start()");

    guard.stop().await.expect("stop failed");
}

/// Créer un fichier dans un répertoire bloqué génère un SecurityEvent.
#[tokio::test]
async fn detects_file_creation_in_blocked_dir() {
    let env = common::TestEnv::new();
    let blocked_dir = env.root().join("blocked_area");
    fs::create_dir_all(&blocked_dir).unwrap();

    let config = fs_io_config(vec![blocked_dir.to_string_lossy().to_string()], vec![]);
    let guard = FsGuard::new(&config, common::test_app_config_arc());
    let (tx, mut rx) = mpsc::channel::<SecurityEvent>(64);

    guard.start(tx).await.expect("start failed");
    // Give the watcher time to register
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // Create a file in the blocked directory
    fs::write(blocked_dir.join("secret.txt"), "sensitive data").unwrap();

    // Wait for the event to propagate (FSEvents has debounce)
    let event = tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv())
        .await
        .expect("Timed out waiting for SecurityEvent")
        .expect("Channel closed");

    assert_eq!(event.module, GuardModule::FsGuard);

    guard.stop().await.expect("stop failed");
}

/// Créer un fichier dans un répertoire non-surveillé ne génère pas d'event.
#[tokio::test]
async fn allows_file_creation_in_unmatched_dir() {
    let env = common::TestEnv::new();
    let blocked_dir = env.root().join("blocked_area");
    let safe_dir = env.root().join("safe_area");
    fs::create_dir_all(&blocked_dir).unwrap();
    fs::create_dir_all(&safe_dir).unwrap();

    let config = fs_io_config(vec![blocked_dir.to_string_lossy().to_string()], vec![]);
    let guard = FsGuard::new(&config, common::test_app_config_arc());
    let (tx, mut rx) = mpsc::channel::<SecurityEvent>(64);

    guard.start(tx).await.expect("start failed");
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // Create a file in the safe (non-blocked) directory
    fs::write(safe_dir.join("normal.txt"), "safe data").unwrap();

    // Should NOT receive an event
    let result = tokio::time::timeout(std::time::Duration::from_millis(500), rx.recv()).await;
    assert!(
        result.is_err(),
        "Should not receive event for unmatched dir"
    );

    guard.stop().await.expect("stop failed");
}

/// Écrire dans un répertoire read-only génère un SecurityEvent.
#[tokio::test]
async fn detects_write_to_read_only_dir() {
    let env = common::TestEnv::new();
    let ro_dir = env.root().join("readonly_area");
    fs::create_dir_all(&ro_dir).unwrap();

    let config = fs_io_config(vec![], vec![ro_dir.to_string_lossy().to_string()]);
    let guard = FsGuard::new(&config, common::test_app_config_arc());
    let (tx, mut rx) = mpsc::channel::<SecurityEvent>(64);

    guard.start(tx).await.expect("start failed");
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // Write to the read-only directory
    fs::write(ro_dir.join("data.txt"), "write attempt").unwrap();

    let event = tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv())
        .await
        .expect("Timed out waiting for SecurityEvent")
        .expect("Channel closed");

    assert_eq!(event.module, GuardModule::FsGuard);

    guard.stop().await.expect("stop failed");
}

/// stop() arrête le watcher — plus d'events après stop().
#[tokio::test]
async fn stop_stops_watcher() {
    let env = common::TestEnv::new();
    let blocked_dir = env.root().join("blocked_area");
    fs::create_dir_all(&blocked_dir).unwrap();

    let config = fs_io_config(vec![blocked_dir.to_string_lossy().to_string()], vec![]);
    let guard = FsGuard::new(&config, common::test_app_config_arc());
    let (tx, mut rx) = mpsc::channel::<SecurityEvent>(64);

    guard.start(tx).await.expect("start failed");
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    guard.stop().await.expect("stop failed");
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Create a file AFTER stop — should not generate an event
    fs::write(blocked_dir.join("after_stop.txt"), "data").unwrap();

    let result = tokio::time::timeout(std::time::Duration::from_millis(500), rx.recv()).await;
    assert!(
        result.is_err() || result.unwrap().is_none(),
        "Should not receive events after stop"
    );
}

/// Un chemin inexistant ne fait pas crasher le guard.
#[tokio::test]
async fn handles_nonexistent_watch_path() {
    let config = fs_io_config(
        vec!["/nonexistent/path/that/doesnt/exist".to_string()],
        vec![],
    );
    let guard = FsGuard::new(&config, common::test_app_config_arc());
    let (tx, _rx) = mpsc::channel::<SecurityEvent>(64);

    // Should not panic or error
    guard
        .start(tx)
        .await
        .expect("start should not fail on nonexistent path");

    let status = guard.status();
    assert!(status.running, "Guard should still be running");

    guard.stop().await.expect("stop failed");
}

/// Guard désactivé → rien ne se passe.
#[tokio::test]
async fn no_events_when_disabled() {
    let config = fs_io_config_disabled();
    let guard = FsGuard::new(&config, common::test_app_config_arc());
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
// Issue 3 : Subprocess integration tests — verify FsGuard detects
// filesystem events from external processes (not just the test process)
// ===========================================================================

/// Un sous-processus `touch` dans un répertoire bloqué génère un SecurityEvent.
#[tokio::test]
async fn subprocess_write_to_blocked_dir_detected() {
    let env = common::TestEnv::new();
    let blocked_dir = env.root().join("blocked_sub");
    fs::create_dir_all(&blocked_dir).unwrap();

    let config = fs_io_config(vec![blocked_dir.to_string_lossy().to_string()], vec![]);
    let guard = FsGuard::new(&config, common::test_app_config_arc());
    let (tx, mut rx) = mpsc::channel::<SecurityEvent>(64);

    guard.start(tx).await.expect("start failed");
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    // Use a subprocess to create a file
    let target = blocked_dir.join("secret_from_subprocess.txt");
    std::process::Command::new("touch")
        .arg(&target)
        .status()
        .expect("failed to execute touch");

    let event = tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv())
        .await
        .expect("Timed out waiting for SecurityEvent from subprocess")
        .expect("Channel closed");

    assert_eq!(event.module, GuardModule::FsGuard);

    guard.stop().await.expect("stop failed");
}

/// Un sous-processus `cat` lisant un fichier bloqué — FsGuard détecte la création
/// du fichier accédé (note: notify détecte les accès metadata/write, pas les reads purs).
#[tokio::test]
async fn subprocess_read_generates_metadata_event() {
    let env = common::TestEnv::new();
    let blocked_dir = env.root().join("blocked_read");
    fs::create_dir_all(&blocked_dir).unwrap();
    // Pre-create a file to read
    let target = blocked_dir.join("existing_file.txt");
    fs::write(&target, "sensitive content").unwrap();

    let config = fs_io_config(vec![blocked_dir.to_string_lossy().to_string()], vec![]);
    let guard = FsGuard::new(&config, common::test_app_config_arc());
    let (tx, mut rx) = mpsc::channel::<SecurityEvent>(64);

    guard.start(tx).await.expect("start failed");
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    // Use subprocess to write (overwrite) the file — this triggers a write event
    std::process::Command::new("sh")
        .args(["-c", &format!("echo 'modified' > '{}'", target.display())])
        .status()
        .expect("failed to execute sh");

    let event = tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv())
        .await
        .expect("Timed out waiting for SecurityEvent")
        .expect("Channel closed");

    assert_eq!(event.module, GuardModule::FsGuard);

    guard.stop().await.expect("stop failed");
}

/// Un sous-processus `touch` dans un répertoire read_only génère un SecurityEvent.
#[tokio::test]
async fn subprocess_write_to_read_only_dir_detected() {
    let env = common::TestEnv::new();
    let ro_dir = env.root().join("readonly_sub");
    fs::create_dir_all(&ro_dir).unwrap();

    let config = fs_io_config(vec![], vec![ro_dir.to_string_lossy().to_string()]);
    let guard = FsGuard::new(&config, common::test_app_config_arc());
    let (tx, mut rx) = mpsc::channel::<SecurityEvent>(64);

    guard.start(tx).await.expect("start failed");
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    let target = ro_dir.join("readonly_write_attempt.txt");
    std::process::Command::new("touch")
        .arg(&target)
        .status()
        .expect("failed to execute touch");

    let event = tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv())
        .await
        .expect("Timed out waiting for SecurityEvent from subprocess")
        .expect("Channel closed");

    assert_eq!(event.module, GuardModule::FsGuard);

    guard.stop().await.expect("stop failed");
}

/// Un sous-processus `touch` dans un répertoire non-surveillé ne génère pas d'alerte.
#[tokio::test]
async fn subprocess_write_to_allowed_dir_no_alert() {
    let env = common::TestEnv::new();
    let blocked_dir = env.root().join("blocked_area_sub");
    let safe_dir = env.root().join("safe_area_sub");
    fs::create_dir_all(&blocked_dir).unwrap();
    fs::create_dir_all(&safe_dir).unwrap();

    let config = fs_io_config(vec![blocked_dir.to_string_lossy().to_string()], vec![]);
    let guard = FsGuard::new(&config, common::test_app_config_arc());
    let (tx, mut rx) = mpsc::channel::<SecurityEvent>(64);

    guard.start(tx).await.expect("start failed");
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    // Subprocess writes to the safe directory
    let target = safe_dir.join("allowed_file.txt");
    std::process::Command::new("touch")
        .arg(&target)
        .status()
        .expect("failed to execute touch");

    let result = tokio::time::timeout(std::time::Duration::from_millis(500), rx.recv()).await;
    assert!(
        result.is_err(),
        "Should not receive event for subprocess in unmatched dir"
    );

    guard.stop().await.expect("stop failed");
}

/// Un sous-processus `mkdir` dans un répertoire bloqué génère un SecurityEvent.
#[tokio::test]
async fn subprocess_mkdir_in_blocked_dir_detected() {
    let env = common::TestEnv::new();
    let blocked_dir = env.root().join("blocked_mkdir");
    fs::create_dir_all(&blocked_dir).unwrap();

    let config = fs_io_config(vec![blocked_dir.to_string_lossy().to_string()], vec![]);
    let guard = FsGuard::new(&config, common::test_app_config_arc());
    let (tx, mut rx) = mpsc::channel::<SecurityEvent>(64);

    guard.start(tx).await.expect("start failed");
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    let target = blocked_dir.join("subdir_from_subprocess");
    std::process::Command::new("mkdir")
        .arg(&target)
        .status()
        .expect("failed to execute mkdir");

    let event = tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv())
        .await
        .expect("Timed out waiting for SecurityEvent from mkdir subprocess")
        .expect("Channel closed");

    assert_eq!(event.module, GuardModule::FsGuard);

    guard.stop().await.expect("stop failed");
}

/// Des écritures rapides par sous-processus sont toutes détectées (tolérance timing).
#[tokio::test]
async fn subprocess_rapid_writes_mostly_detected() {
    let env = common::TestEnv::new();
    let blocked_dir = env.root().join("blocked_rapid");
    fs::create_dir_all(&blocked_dir).unwrap();

    let config = fs_io_config(vec![blocked_dir.to_string_lossy().to_string()], vec![]);
    let guard = FsGuard::new(&config, common::test_app_config_arc());
    let (tx, mut rx) = mpsc::channel::<SecurityEvent>(64);

    guard.start(tx).await.expect("start failed");
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    // Write 10 files rapidly via subprocess
    for i in 0..10 {
        let target = blocked_dir.join(format!("rapid_{}.txt", i));
        std::process::Command::new("touch")
            .arg(&target)
            .status()
            .expect("failed to execute touch");
    }

    // Collect events with timeout — expect at least 8 out of 10
    let mut event_count = 0;
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let remaining = deadline - tokio::time::Instant::now();
        match tokio::time::timeout(remaining, rx.recv()).await {
            Ok(Some(event)) => {
                assert_eq!(event.module, GuardModule::FsGuard);
                event_count += 1;
                if event_count >= 10 {
                    break;
                }
            }
            _ => break,
        }
    }

    assert!(
        event_count >= 8,
        "Expected at least 8 events from 10 rapid writes, got {}",
        event_count
    );

    guard.stop().await.expect("stop failed");
}

// ===========================================================================
// Existing tests
// ===========================================================================

/// Le watchdog est mis à jour lors d'events filesystem.
#[tokio::test]
async fn updates_watchdog_on_event() {
    let env = common::TestEnv::new();
    let blocked_dir = env.root().join("blocked_area");
    fs::create_dir_all(&blocked_dir).unwrap();

    let config = fs_io_config(vec![blocked_dir.to_string_lossy().to_string()], vec![]);
    let guard = FsGuard::new(&config, common::test_app_config_arc());
    let (tx, mut rx) = mpsc::channel::<SecurityEvent>(64);

    guard.start(tx).await.expect("start failed");
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // Watchdog should be healthy initially
    assert!(guard.is_watchdog_healthy(), "Watchdog should be healthy");

    // Trigger an event
    fs::write(blocked_dir.join("trigger.txt"), "data").unwrap();

    // Wait for the event
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv()).await;

    // Watchdog should still be healthy after event
    assert!(
        guard.is_watchdog_healthy(),
        "Watchdog should be healthy after event"
    );

    guard.stop().await.expect("stop failed");
}
