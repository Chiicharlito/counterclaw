//! Tests for BUG 4 — Kill Switch: Implement actual process killing (HIGH)
//!
//! KillSwitch.execute() only logs. Add watch_processes to config,
//! implement kill/suspend logic using ProcessScanner + kill_process().

mod common;

use counterclaw::config::KillSwitchConfig;

// ---------------------------------------------------------------------------
// Test 1: Config backward compatible — no watch_processes field → empty vec
// ---------------------------------------------------------------------------
#[test]
fn kill_switch_config_backward_compatible() {
    let yaml = r#"
enabled: true
threshold_severity: warning
threshold_count: 3
threshold_window_seconds: 60
action: alert_only
"#;
    let config: KillSwitchConfig = serde_yaml::from_str(yaml).unwrap();
    assert!(
        config.watch_processes.is_empty(),
        "Default watch_processes should be empty"
    );
}

// ---------------------------------------------------------------------------
// Test 2: Config with watch_processes is parsed
// ---------------------------------------------------------------------------
#[test]
fn kill_switch_watch_processes_parsed() {
    let yaml = r#"
enabled: true
threshold_severity: warning
threshold_count: 3
threshold_window_seconds: 60
action: suspend_openclaw
watch_processes:
  - "openclaw"
  - "node.*openclaw"
"#;
    let config: KillSwitchConfig = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(config.watch_processes.len(), 2);
    assert_eq!(config.watch_processes[0], "openclaw");
    assert_eq!(config.watch_processes[1], "node.*openclaw");
}

// ---------------------------------------------------------------------------
// Test 3: action="alert_only" → no process kill attempt
// ---------------------------------------------------------------------------
#[test]
fn kill_switch_action_alert_only_no_kill() {
    let yaml = r#"
enabled: true
threshold_severity: warning
threshold_count: 3
threshold_window_seconds: 60
action: alert_only
watch_processes:
  - "openclaw"
"#;
    let config: KillSwitchConfig = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(config.action, "alert_only");
    // When action is alert_only, kill_switch_should_kill returns false
    assert!(
        !counterclaw::alerting::engine::kill_switch_should_kill(&config.action),
        "alert_only should not trigger process killing"
    );
}

// ---------------------------------------------------------------------------
// Test 4: action="kill" → should attempt process killing
// ---------------------------------------------------------------------------
#[test]
fn kill_switch_action_kill_attempts_process_lookup() {
    assert!(
        counterclaw::alerting::engine::kill_switch_should_kill("kill"),
        "'kill' action should trigger process killing"
    );
}

// ---------------------------------------------------------------------------
// Test 5: action="suspend_openclaw" same behavior as "kill"
// ---------------------------------------------------------------------------
#[test]
fn kill_switch_action_suspend_same_as_kill() {
    assert!(
        counterclaw::alerting::engine::kill_switch_should_kill("suspend_openclaw"),
        "'suspend_openclaw' action should trigger process killing"
    );
}
