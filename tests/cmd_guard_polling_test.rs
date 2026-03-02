//! Tests for BUG 3 — Cmd Guard: Configurable poll interval (HIGH)
//!
//! Hardcoded 2s polling is too slow for ephemeral processes.
//! Add configurable poll_interval_ms with backward-compatible defaults.

mod common;

use counterclaw::config::{AppConfig, CmdGuardConfig, NetGuardConfig};

// ---------------------------------------------------------------------------
// Test 1: Default poll interval is 500ms for cmd_guard
// ---------------------------------------------------------------------------
#[test]
fn default_cmd_poll_interval_is_500ms() {
    // Parse a config YAML without poll_interval_ms → should default to 500
    let yaml = r#"
enabled: true
blacklist: []
require_approval: []
monitoring_method: log_only
"#;
    let config: CmdGuardConfig = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(
        config.poll_interval_ms, 500,
        "Default cmd poll interval should be 500ms"
    );
}

// ---------------------------------------------------------------------------
// Test 2: Custom poll interval is respected
// ---------------------------------------------------------------------------
#[test]
fn custom_cmd_poll_interval_respected() {
    let yaml = r#"
enabled: true
blacklist: []
require_approval: []
monitoring_method: log_only
poll_interval_ms: 1000
"#;
    let config: CmdGuardConfig = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(
        config.poll_interval_ms, 1000,
        "Custom poll interval should be 1000ms"
    );
}

// ---------------------------------------------------------------------------
// Test 3: Backward compatibility — old YAML without poll_interval_ms parses
// ---------------------------------------------------------------------------
#[test]
fn config_backward_compatible() {
    let env = common::TestEnv::new();
    let yaml = common::minimal_monitor_config(&env);
    // The minimal config doesn't have poll_interval_ms — should still parse
    let config: AppConfig = serde_yaml::from_str(&yaml).unwrap();
    assert_eq!(config.cmd_guard.poll_interval_ms, 500);
    assert_eq!(config.net_guard.poll_interval_ms, 3000);
}

// ---------------------------------------------------------------------------
// Test 4: Default net_guard poll interval is 3000ms
// ---------------------------------------------------------------------------
#[test]
fn default_net_poll_interval_is_3000ms() {
    let yaml = r#"
enabled: true
watch_processes: []
allowed_egress: []
max_post_payload_bytes: 51200
block_unknown_post: false
alert_on_unknown_dns: false
enforcement_method: log_only
"#;
    let config: NetGuardConfig = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(
        config.poll_interval_ms, 3000,
        "Default net poll interval should be 3000ms"
    );
}
