//! Security tests for config hardening

mod common;

use counterclaw::config::*;

// Step 2.5 — ReDoS protection

#[test]
fn rejects_nested_quantifier_pattern() {
    assert!(!is_safe_regex("(a+)+"));
    assert!(!is_safe_regex("(.*)*"));
    assert!(!is_safe_regex("(a+)*"));
    assert!(!is_safe_regex("(x*)+"));
}

#[test]
fn accepts_safe_regex_patterns() {
    assert!(is_safe_regex(r"password|secret"));
    assert!(is_safe_regex(r"\d{3}-\d{3}-\d{4}"));
    assert!(is_safe_regex(r"[a-zA-Z]+"));
    assert!(is_safe_regex(r"AKIA[0-9A-Z]{16}"));
}

#[test]
fn compile_safe_regex_rejects_dangerous() {
    let result = compile_safe_regex("(a+)+");
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("nested quantifiers"));
}

#[test]
fn compile_safe_regex_accepts_valid() {
    let result = compile_safe_regex(r"password|secret");
    assert!(result.is_ok());
}

// Step 3.3 — YAML bomb protection

#[test]
fn rejects_oversized_config_file() {
    let env = common::TestEnv::new();
    let huge_path = env.root().join("huge.yaml");
    // Create a file > 1MB
    let huge_content = "a".repeat(MAX_CONFIG_FILE_SIZE + 1);
    std::fs::write(&huge_path, &huge_content).unwrap();

    let result = AppConfig::load(&huge_path);
    assert!(result.is_err());
}

// Step 2.8 — Webhook from env

#[test]
fn slack_webhook_url_prefers_env_variable() {
    // V8: Environment variable is now IGNORED for security.
    // An agent could set env vars to redirect notifications to an attacker URL.
    // The webhook URL is only read from the config file (protected by SELF_PROTECTION_PATHS).
    let env = common::TestEnv::new();
    env.write_default_config();
    let config = AppConfig::load(&env.config_path()).unwrap();

    // Set env variable — should be IGNORED
    std::env::set_var(
        "COUNTERCLAW_SLACK_WEBHOOK",
        "https://hooks.slack.com/test-from-env",
    );
    let url = config.slack_webhook_url();
    std::env::remove_var("COUNTERCLAW_SLACK_WEBHOOK");

    // V8: Should return config value, not env var
    assert_eq!(url, config.alerting.slack.webhook_url);
}

#[test]
fn slack_webhook_url_falls_back_to_config() {
    let env = common::TestEnv::new();
    env.write_default_config();
    let config = AppConfig::load(&env.config_path()).unwrap();

    // Make sure env var is not set
    std::env::remove_var("COUNTERCLAW_SLACK_WEBHOOK");
    let url = config.slack_webhook_url();

    // Should use the value from config
    assert_eq!(url, config.alerting.slack.webhook_url);
}
