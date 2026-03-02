//! Tests pour ProcessMonitor trait et ses implémentations.
//!
//! Tests pour :
//! - DetectedProcess struct
//! - KqueueMonitor (macOS) — détection en temps réel
//! - PollingMonitor (fallback) — détection par polling

mod common;

use counterclaw::guards::process_monitor::DetectedProcess;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

// ===========================================================================
// DetectedProcess
// ===========================================================================

/// DetectedProcess capture correctement pid, name, cmd.
#[test]
fn detected_process_captures_pid_name_cmd() {
    let dp = DetectedProcess {
        pid: 42,
        name: "evil_agent".to_string(),
        cmd: vec!["evil_agent".to_string(), "--exfiltrate".to_string()],
    };
    assert_eq!(dp.pid, 42);
    assert_eq!(dp.name, "evil_agent");
    assert_eq!(dp.cmd, vec!["evil_agent", "--exfiltrate"]);
}

// ===========================================================================
// KqueueMonitor (macOS only)
// ===========================================================================

/// KqueueMonitor détecte un processus spawnné (sleep 1).
#[cfg(target_os = "macos")]
#[tokio::test]
async fn kqueue_monitor_detects_spawned_process() {
    use counterclaw::guards::kqueue_monitor::KqueueMonitor;
    use counterclaw::guards::process_monitor::ProcessMonitor;

    let monitor = KqueueMonitor::new(vec!["sleep".to_string()]);
    let (tx, mut rx) = mpsc::channel::<DetectedProcess>(64);
    let token = CancellationToken::new();

    let token_clone = token.clone();
    let handle = tokio::spawn(async move {
        monitor.start(tx, token_clone).await.unwrap();
    });

    // Give the monitor a moment to set up
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // Drain any pre-existing sleep detections (stale from other tests in full suite)
    while let Ok(Some(_)) =
        tokio::time::timeout(std::time::Duration::from_millis(200), rx.recv()).await
    {
        // discard stale events
    }

    // Spawn a process that matches watch patterns
    let child = std::process::Command::new("sleep")
        .arg("2")
        .spawn()
        .expect("failed to spawn sleep");

    // Wait for detection of our specific PID (skip events for stale sleep processes)
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    let mut detected = None;
    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout_at(deadline, rx.recv()).await {
            Ok(Some(dp)) if dp.pid == child.id() => {
                detected = Some(dp);
                break;
            }
            Ok(Some(_)) => continue, // skip stale detections
            _ => break,
        }
    }
    let detected = detected.expect("Timed out waiting for process detection");

    assert_eq!(detected.pid, child.id());
    assert!(
        detected.name.contains("sleep"),
        "Name should contain 'sleep', got '{}'",
        detected.name
    );

    token.cancel();
    let _ = handle.await;
}

/// KqueueMonitor ignore les processus non-surveillés.
#[cfg(target_os = "macos")]
#[tokio::test]
async fn kqueue_monitor_ignores_unwatched_process() {
    use counterclaw::guards::kqueue_monitor::KqueueMonitor;
    use counterclaw::guards::process_monitor::ProcessMonitor;

    let monitor = KqueueMonitor::new(vec!["zzz_nonexistent_pattern".to_string()]);
    let (tx, mut rx) = mpsc::channel::<DetectedProcess>(64);
    let token = CancellationToken::new();

    let token_clone = token.clone();
    let handle = tokio::spawn(async move {
        monitor.start(tx, token_clone).await.unwrap();
    });

    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // Spawn a process that does NOT match watch patterns
    let _child = std::process::Command::new("echo")
        .arg("hello")
        .spawn()
        .expect("failed to spawn echo");

    // Should NOT receive a detection
    let result = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv()).await;
    assert!(
        result.is_err(),
        "Should not detect process that doesn't match patterns"
    );

    token.cancel();
    let _ = handle.await;
}

/// KqueueMonitor détecte un processus court (50ms) — que le PollingMonitor (2s) raterait.
/// Note: sans NOTE_TRACK (bloqué par SIP sur macOS moderne), les processus < 50ms
/// peuvent être ratés par le scan hybride. Ceci reste 40x plus rapide que le polling pur.
#[cfg(target_os = "macos")]
#[tokio::test]
async fn kqueue_monitor_detects_short_lived_process() {
    use counterclaw::guards::kqueue_monitor::KqueueMonitor;
    use counterclaw::guards::process_monitor::ProcessMonitor;

    let monitor = KqueueMonitor::new(vec!["sleep".to_string()]);
    let (tx, mut rx) = mpsc::channel::<DetectedProcess>(64);
    let token = CancellationToken::new();

    let token_clone = token.clone();
    let handle = tokio::spawn(async move {
        monitor.start(tx, token_clone).await.unwrap();
    });

    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // sleep 0.05 lives ~50ms — too short for PollingMonitor (2s interval)
    // but catchable by KqueueMonitor's 50ms scan + kqueue events
    let _child = std::process::Command::new("sleep")
        .arg("0.05")
        .spawn()
        .expect("failed to spawn sleep");

    let detected = tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv())
        .await
        .expect("Timed out — kqueue hybrid scan should catch short-lived processes")
        .expect("Channel closed");

    assert!(
        detected.name.contains("sleep"),
        "Should detect short-lived sleep process, got '{}'",
        detected.name
    );

    token.cancel();
    let _ = handle.await;
}

// ===========================================================================
// PollingMonitor (fallback)
// ===========================================================================

/// PollingMonitor détecte un processus long-running.
#[tokio::test]
async fn polling_monitor_detects_long_running_process() {
    use counterclaw::guards::polling_monitor::PollingMonitor;
    use counterclaw::guards::process_monitor::ProcessMonitor;

    let monitor = PollingMonitor::new(
        vec!["sleep".to_string()],
        std::time::Duration::from_millis(500),
    );
    let (tx, mut rx) = mpsc::channel::<DetectedProcess>(64);
    let token = CancellationToken::new();

    let token_clone = token.clone();
    let handle = tokio::spawn(async move {
        monitor.start(tx, token_clone).await.unwrap();
    });

    // Spawn a long-running process
    let _child = std::process::Command::new("sleep")
        .arg("10")
        .spawn()
        .expect("failed to spawn sleep");

    let detected = tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv())
        .await
        .expect("Timed out — polling should detect long-running process")
        .expect("Channel closed");

    assert!(
        detected.name.contains("sleep"),
        "Should detect sleep process, got '{}'",
        detected.name
    );

    token.cancel();
    let _ = handle.await;
}

/// PollingMonitor rate les processus éphémères — limitation connue documentée.
#[tokio::test]
async fn polling_monitor_misses_ephemeral_by_design() {
    use counterclaw::guards::polling_monitor::PollingMonitor;
    use counterclaw::guards::process_monitor::ProcessMonitor;

    let monitor = PollingMonitor::new(
        vec!["echo".to_string()],
        std::time::Duration::from_secs(2), // slow poll
    );
    let (tx, mut rx) = mpsc::channel::<DetectedProcess>(64);
    let token = CancellationToken::new();

    let token_clone = token.clone();
    let handle = tokio::spawn(async move {
        monitor.start(tx, token_clone).await.unwrap();
    });

    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // echo exits immediately — polling will miss it
    let _child = std::process::Command::new("echo")
        .arg("you_wont_catch_me")
        .spawn()
        .expect("failed to spawn echo");

    let result = tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv()).await;
    // Polling is expected to miss ephemeral processes — this is a known limitation
    assert!(
        result.is_err(),
        "Polling should miss ephemeral process (known limitation)"
    );

    token.cancel();
    let _ = handle.await;
}
