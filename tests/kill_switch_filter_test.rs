//! Tests for BUG 5 — Kill Switch: Filter Keychain false positives (MEDIUM)
//!
//! macOS Keychain generates 700+ filesystem events that are normal system behavior.
//! FS Guard classifies them as Critical → kill switch triggers on noise.

mod common;

use counterclaw::alerting::engine::should_exclude_from_kill_switch;
use counterclaw::config::KillSwitchConfig;
use counterclaw::types::{ActionTaken, GuardModule, SecurityEvent, Severity};

// ---------------------------------------------------------------------------
// Test 1: Keychain events are excluded from kill switch counting
// ---------------------------------------------------------------------------
#[test]
fn kill_switch_excludes_keychain_events() {
    let patterns = vec![
        "Library/Keychains".to_string(),
        "login.keychain".to_string(),
    ];

    let event = SecurityEvent::new(
        GuardModule::FsGuard,
        Severity::Critical,
        ActionTaken::Blocked,
        "Blocked access to ~/Library/Keychains/login.keychain-db".to_string(),
    );

    assert!(
        should_exclude_from_kill_switch(&event, &patterns),
        "Keychain event should be excluded from kill switch"
    );
}

// ---------------------------------------------------------------------------
// Test 2: Normal events are NOT excluded
// ---------------------------------------------------------------------------
#[test]
fn kill_switch_counts_non_excluded_events() {
    let patterns = vec![
        "Library/Keychains".to_string(),
        "login.keychain".to_string(),
    ];

    let event = SecurityEvent::new(
        GuardModule::FsGuard,
        Severity::Critical,
        ActionTaken::Blocked,
        "Blocked access to ~/.ssh/id_rsa".to_string(),
    );

    assert!(
        !should_exclude_from_kill_switch(&event, &patterns),
        "SSH key event should NOT be excluded"
    );
}

// ---------------------------------------------------------------------------
// Test 3: exclude_path_patterns config default is empty
// ---------------------------------------------------------------------------
#[test]
fn exclude_patterns_config_parsing() {
    let yaml = r#"
enabled: true
threshold_severity: warning
threshold_count: 3
threshold_window_seconds: 60
action: alert_only
exclude_path_patterns:
  - "Library/Keychains"
  - "login.keychain"
"#;
    let config: KillSwitchConfig = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(config.exclude_path_patterns.len(), 2);
}

// ---------------------------------------------------------------------------
// Test 4: Backward compatible — no exclude_path_patterns field → empty
// ---------------------------------------------------------------------------
#[test]
fn exclude_patterns_backward_compatible() {
    let yaml = r#"
enabled: true
threshold_severity: warning
threshold_count: 3
threshold_window_seconds: 60
action: alert_only
"#;
    let config: KillSwitchConfig = serde_yaml::from_str(yaml).unwrap();
    assert!(config.exclude_path_patterns.is_empty());
}

// ---------------------------------------------------------------------------
// Test 5: Non-FsGuard events are never excluded (regardless of description)
// ---------------------------------------------------------------------------
#[test]
fn non_fs_guard_events_never_excluded() {
    let patterns = vec!["Library/Keychains".to_string()];

    // A CdpProxy event with a description mentioning Keychains → still NOT excluded
    let event = SecurityEvent::new(
        GuardModule::CdpProxy,
        Severity::Critical,
        ActionTaken::Blocked,
        "Something about Library/Keychains".to_string(),
    );

    assert!(
        !should_exclude_from_kill_switch(&event, &patterns),
        "Non-FsGuard events should never be excluded regardless of description"
    );
}
