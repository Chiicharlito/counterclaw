//! Tests for the Slack notification backend.
//!
//! Pure logic tests only — no real HTTP calls.
//! Tests cover: message formatting, severity filtering, sanitization, edge cases.

mod common;

use counterclaw::alerting::slack::SlackNotifier;
use counterclaw::config::SlackConfig;
use counterclaw::types::{ActionTaken, GuardModule, SecurityEvent, Severity};

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

fn test_config() -> SlackConfig {
    SlackConfig {
        enabled: true,
        webhook_url: "https://hooks.slack.com/services/TEST/TEST/TEST".to_string(),
        channel: "#test-alerts".to_string(),
        min_severity: "warning".to_string(),
    }
}

fn make_event(severity: Severity, module: GuardModule, desc: &str) -> SecurityEvent {
    SecurityEvent::new(module, severity, ActionTaken::Blocked, desc.to_string())
}

// ---------------------------------------------------------------------------
// Format tests — verify Block Kit message structure
// ---------------------------------------------------------------------------

#[test]
fn format_includes_severity() {
    let notifier = SlackNotifier::new(&test_config());
    let event = make_event(Severity::Critical, GuardModule::FsGuard, "Test alert");
    let msg = notifier.format_message(&event);
    let msg_str = serde_json::to_string(&msg).unwrap();
    assert!(
        msg_str.contains("CRIT"),
        "Should contain severity: {}",
        msg_str
    );
}

#[test]
fn format_includes_module() {
    let notifier = SlackNotifier::new(&test_config());
    let event = make_event(Severity::High, GuardModule::CdpProxy, "CDP alert");
    let msg = notifier.format_message(&event);
    let msg_str = serde_json::to_string(&msg).unwrap();
    assert!(
        msg_str.contains("cdp_proxy"),
        "Should contain module name: {}",
        msg_str
    );
}

#[test]
fn format_includes_description() {
    let notifier = SlackNotifier::new(&test_config());
    let event = make_event(Severity::Warning, GuardModule::System, "Something happened");
    let msg = notifier.format_message(&event);
    let msg_str = serde_json::to_string(&msg).unwrap();
    assert!(
        msg_str.contains("Something happened"),
        "Should contain description"
    );
}

#[test]
fn format_includes_timestamp() {
    let notifier = SlackNotifier::new(&test_config());
    let event = make_event(Severity::Warning, GuardModule::System, "Test");
    let msg = notifier.format_message(&event);
    let msg_str = serde_json::to_string(&msg).unwrap();
    assert!(
        msg_str.contains("UTC"),
        "Should contain timestamp with UTC: {}",
        msg_str
    );
}

#[test]
fn format_includes_event_id() {
    let notifier = SlackNotifier::new(&test_config());
    let event = make_event(Severity::Warning, GuardModule::System, "Test");
    let msg = notifier.format_message(&event);
    let msg_str = serde_json::to_string(&msg).unwrap();
    assert!(
        msg_str.contains("Event ID:"),
        "Should contain event ID label: {}",
        msg_str
    );
    assert!(
        msg_str.contains(&event.id),
        "Should contain the actual event ID: {}",
        msg_str
    );
}

#[test]
fn format_includes_channel() {
    let notifier = SlackNotifier::new(&test_config());
    let event = make_event(Severity::Warning, GuardModule::System, "Test");
    let msg = notifier.format_message(&event);
    let msg_str = serde_json::to_string(&msg).unwrap();
    assert!(
        msg_str.contains("#test-alerts"),
        "Should contain channel name: {}",
        msg_str
    );
}

#[test]
fn format_uses_correct_emoji_for_each_severity() {
    let notifier = SlackNotifier::new(&test_config());

    let info_msg =
        notifier.format_message(&make_event(Severity::Info, GuardModule::System, "info"));
    let info_str = serde_json::to_string(&info_msg).unwrap();
    // serde_json outputs raw UTF-8, not \uXXXX escapes
    assert!(
        info_str.contains("\u{2139}"),
        "Info should use info emoji: {}",
        info_str
    );

    let critical_msg = notifier.format_message(&make_event(
        Severity::Critical,
        GuardModule::System,
        "critical",
    ));
    let critical_str = serde_json::to_string(&critical_msg).unwrap();
    assert!(
        critical_str.contains("\u{1F6A8}"),
        "Critical should use siren emoji: {}",
        critical_str
    );
}

#[test]
fn format_has_blocks_array() {
    let notifier = SlackNotifier::new(&test_config());
    let event = make_event(Severity::Warning, GuardModule::System, "Test");
    let msg = notifier.format_message(&event);

    assert!(msg["blocks"].is_array(), "Message should have blocks array");
    let blocks = msg["blocks"].as_array().unwrap();
    assert!(
        blocks.len() >= 3,
        "Should have at least 3 blocks (header, section, context), got {}",
        blocks.len()
    );
}

// ---------------------------------------------------------------------------
// should_notify tests — severity filtering logic
// ---------------------------------------------------------------------------

#[test]
fn should_notify_respects_min_severity() {
    let notifier = SlackNotifier::new(&test_config()); // min_severity = warning
    let info_event = make_event(Severity::Info, GuardModule::System, "Info");
    assert!(
        !notifier.should_notify(&info_event),
        "Info should be below warning threshold"
    );
}

#[test]
fn should_notify_passes_high() {
    let notifier = SlackNotifier::new(&test_config()); // min_severity = warning

    let critical_event = make_event(Severity::Critical, GuardModule::System, "Critical");
    assert!(
        notifier.should_notify(&critical_event),
        "Critical should pass warning threshold"
    );

    let high_event = make_event(Severity::High, GuardModule::System, "High");
    assert!(
        notifier.should_notify(&high_event),
        "High should pass warning threshold"
    );

    let warning_event = make_event(Severity::Warning, GuardModule::System, "Warning");
    assert!(
        notifier.should_notify(&warning_event),
        "Warning should pass warning threshold (equal)"
    );
}

#[test]
fn should_notify_false_when_disabled() {
    let config = SlackConfig {
        enabled: false,
        webhook_url: "https://hooks.slack.com/test".to_string(),
        channel: "#test".to_string(),
        min_severity: "info".to_string(),
    };
    let notifier = SlackNotifier::new(&config);
    let event = make_event(Severity::Critical, GuardModule::System, "Critical");
    assert!(
        !notifier.should_notify(&event),
        "Disabled notifier should not notify"
    );
}

// ---------------------------------------------------------------------------
// Construction tests — severity parsing, is_enabled
// ---------------------------------------------------------------------------

#[test]
fn new_parses_severity() {
    // min_severity = "high" -> should skip Warning
    let config = SlackConfig {
        enabled: true,
        webhook_url: "https://hooks.slack.com/test".to_string(),
        channel: "#test".to_string(),
        min_severity: "high".to_string(),
    };
    let notifier = SlackNotifier::new(&config);

    let warning = make_event(Severity::Warning, GuardModule::System, "Warning");
    assert!(
        !notifier.should_notify(&warning),
        "Warning should not pass high threshold"
    );

    let high = make_event(Severity::High, GuardModule::System, "High");
    assert!(
        notifier.should_notify(&high),
        "High should pass high threshold"
    );
}

#[test]
fn new_parses_unknown_severity_as_info() {
    let config = SlackConfig {
        enabled: true,
        webhook_url: "https://hooks.slack.com/test".to_string(),
        channel: "#test".to_string(),
        min_severity: "banana".to_string(),
    };
    let notifier = SlackNotifier::new(&config);

    // Unknown defaults to Info, so even Info events should be notified
    let info_event = make_event(Severity::Info, GuardModule::System, "Info");
    assert!(
        notifier.should_notify(&info_event),
        "Unknown severity should default to Info (lowest), allowing all events"
    );
}

#[test]
fn is_enabled_returns_config_value() {
    let enabled_config = test_config();
    let notifier = SlackNotifier::new(&enabled_config);
    assert!(
        notifier.is_enabled(),
        "Should be enabled when config says so"
    );

    let disabled_config = SlackConfig {
        enabled: false,
        ..test_config()
    };
    let notifier = SlackNotifier::new(&disabled_config);
    assert!(
        !notifier.is_enabled(),
        "Should be disabled when config says so"
    );
}

// ---------------------------------------------------------------------------
// Sanitization tests — XSS/injection prevention
// ---------------------------------------------------------------------------

#[test]
fn format_sanitizes_special_chars() {
    let notifier = SlackNotifier::new(&test_config());
    let event = make_event(
        Severity::Warning,
        GuardModule::System,
        "Test <script>alert('xss')</script> & more",
    );
    let msg = notifier.format_message(&event);
    let msg_str = serde_json::to_string(&msg).unwrap();

    // Should not contain raw < > &
    assert!(
        !msg_str.contains("<script>"),
        "Should sanitize < > characters"
    );
    assert!(
        msg_str.contains("&lt;script&gt;"),
        "Should escape < to &lt;"
    );
}

#[test]
fn format_sanitizes_ampersand() {
    let notifier = SlackNotifier::new(&test_config());
    let event = make_event(Severity::Warning, GuardModule::System, "foo & bar");
    let msg = notifier.format_message(&event);
    let msg_str = serde_json::to_string(&msg).unwrap();
    assert!(
        msg_str.contains("foo &amp; bar"),
        "Should escape & to &amp;: {}",
        msg_str
    );
}

// ---------------------------------------------------------------------------
// Edge case tests
// ---------------------------------------------------------------------------

#[test]
fn format_handles_empty_description() {
    let notifier = SlackNotifier::new(&test_config());
    let event = make_event(Severity::Warning, GuardModule::System, "");
    let msg = notifier.format_message(&event);

    // Should still produce valid JSON
    let msg_str = serde_json::to_string(&msg).unwrap();
    assert!(
        !msg_str.is_empty(),
        "Empty description should still produce valid JSON"
    );

    // Verify it parses back correctly
    let _parsed: serde_json::Value = serde_json::from_str(&msg_str).unwrap();
}

#[test]
fn format_handles_very_long_description() {
    let notifier = SlackNotifier::new(&test_config());
    let long_desc = "A".repeat(5000);
    let event = make_event(Severity::Warning, GuardModule::System, &long_desc);
    let msg = notifier.format_message(&event);

    // Should still produce valid JSON without panic
    let msg_str = serde_json::to_string(&msg).unwrap();
    assert!(
        msg_str.contains("AAAA"),
        "Should contain the long description"
    );

    let _parsed: serde_json::Value = serde_json::from_str(&msg_str).unwrap();
}

#[test]
fn format_handles_unicode_description() {
    let notifier = SlackNotifier::new(&test_config());
    let event = make_event(
        Severity::Warning,
        GuardModule::System,
        "Alerte fichier: /home/utilisateur/.ssh/cle_privee",
    );
    let msg = notifier.format_message(&event);
    let msg_str = serde_json::to_string(&msg).unwrap();
    assert!(
        msg_str.contains("Alerte fichier"),
        "Should handle unicode in description"
    );
}

#[test]
fn format_handles_all_guard_modules() {
    let notifier = SlackNotifier::new(&test_config());

    let modules = vec![
        (GuardModule::FsGuard, "fs_guard"),
        (GuardModule::CdpProxy, "cdp_proxy"),
        (GuardModule::NetGuard, "net_guard"),
        (GuardModule::CmdGuard, "cmd_guard"),
        (GuardModule::System, "system"),
    ];

    for (module, expected_str) in modules {
        let event = make_event(Severity::Warning, module, "Test");
        let msg = notifier.format_message(&event);
        let msg_str = serde_json::to_string(&msg).unwrap();
        assert!(
            msg_str.contains(expected_str),
            "Should contain module name '{}': {}",
            expected_str,
            msg_str
        );
    }
}
