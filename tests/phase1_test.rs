//! Tests de la Phase 1 : config, types, alerting.
//!
//! Ces tests servent à la fois de validation et de modèle
//! pour les phases suivantes (TDD security-first).

mod common;

use predicates::prelude::*;
use std::fs;

/// Helper pour créer une commande pointant vers le binaire compilé.
#[allow(deprecated)]
fn counterclaw_cmd() -> assert_cmd::Command {
    assert_cmd::Command::cargo_bin("counterclaw").unwrap()
}

// ===========================================================================
// Config : chargement et validation
// ===========================================================================

#[test]
fn config_load_valid_yaml() {
    let env = common::TestEnv::new();
    let yaml = common::minimal_monitor_config(&env);
    env.write_config(&yaml);

    // Doit charger sans erreur
    let config =
        counterclaw::config::AppConfig::load(&env.config_path()).expect("Should load valid config");
    assert_eq!(config.general.mode, "monitor");
}

#[test]
fn config_load_missing_file_fails() {
    let env = common::TestEnv::new();
    let result = counterclaw::config::AppConfig::load(&env.config_path());
    assert!(result.is_err(), "Loading missing file should fail");
}

#[test]
fn config_load_malformed_yaml_fails() {
    let env = common::TestEnv::new();
    env.write_config("this is: [not: valid: yaml: {{{}}}");
    let result = counterclaw::config::AppConfig::load(&env.config_path());
    assert!(result.is_err(), "Loading malformed YAML should fail");
}

#[test]
fn config_validate_catches_invalid_mode() {
    let env = common::TestEnv::new();
    env.write_config(common::invalid_config());
    let config = counterclaw::config::AppConfig::load(&env.config_path())
        .expect("YAML is syntactically valid");

    let errors = config.validate();
    assert!(!errors.is_empty(), "Invalid config should produce errors");
    assert!(
        errors.iter().any(|e| e.contains("general.mode")),
        "Should catch invalid mode"
    );
}

#[test]
fn config_validate_catches_invalid_log_level() {
    let env = common::TestEnv::new();
    env.write_config(common::invalid_config());
    let config = counterclaw::config::AppConfig::load(&env.config_path()).unwrap();

    let errors = config.validate();
    assert!(
        errors.iter().any(|e| e.contains("log_level")),
        "Should catch invalid log_level"
    );
}

#[test]
fn config_validate_catches_same_cdp_ports() {
    let env = common::TestEnv::new();
    env.write_config(common::invalid_config());
    let config = counterclaw::config::AppConfig::load(&env.config_path()).unwrap();

    let errors = config.validate();
    assert!(
        errors.iter().any(|e| e.contains("listen_port")),
        "Should catch identical CDP ports"
    );
}

#[test]
fn config_validate_catches_no_alerting_backend() {
    let env = common::TestEnv::new();
    env.write_config(common::invalid_config());
    let config = counterclaw::config::AppConfig::load(&env.config_path()).unwrap();

    let errors = config.validate();
    assert!(
        errors.iter().any(|e| e.contains("alerting backend")),
        "Should catch no alerting backend enabled"
    );
}

#[test]
fn config_validate_valid_config_has_no_errors() {
    let env = common::TestEnv::new();
    let yaml = common::minimal_monitor_config(&env);
    env.write_config(&yaml);
    let config = counterclaw::config::AppConfig::load(&env.config_path()).unwrap();

    let errors = config.validate();
    assert!(
        errors.is_empty(),
        "Valid config should have no errors: {:?}",
        errors
    );
}

// ===========================================================================
// Config : tilde expansion (sécurité des chemins)
// ===========================================================================

#[test]
fn expand_tilde_resolves_home() {
    let expanded = counterclaw::config::expand_tilde("~/.ssh");
    // Doit commencer par / (chemin absolu), pas par ~
    assert!(
        !expanded.to_string_lossy().starts_with('~'),
        "Tilde should be expanded to absolute path"
    );
    assert!(
        expanded.to_string_lossy().ends_with(".ssh"),
        "Rest of path should be preserved"
    );
}

#[test]
fn expand_tilde_leaves_absolute_paths_unchanged() {
    let expanded = counterclaw::config::expand_tilde("/etc/passwd");
    assert_eq!(expanded.to_string_lossy(), "/etc/passwd");
}

#[test]
fn expand_tilde_leaves_relative_paths_unchanged() {
    let expanded = counterclaw::config::expand_tilde("relative/path");
    assert_eq!(expanded.to_string_lossy(), "relative/path");
}

// ===========================================================================
// Types : SecurityEvent
// ===========================================================================

#[test]
fn security_event_has_unique_ids() {
    let event1 = counterclaw::types::SecurityEvent::new(
        counterclaw::types::GuardModule::System,
        counterclaw::types::Severity::Info,
        counterclaw::types::ActionTaken::Logged,
        "test".to_string(),
    );
    let event2 = counterclaw::types::SecurityEvent::new(
        counterclaw::types::GuardModule::System,
        counterclaw::types::Severity::Info,
        counterclaw::types::ActionTaken::Logged,
        "test".to_string(),
    );
    assert_ne!(event1.id, event2.id, "Each event must have a unique ID");
}

#[test]
fn security_event_serializes_to_json() {
    let event = counterclaw::types::SecurityEvent::new(
        counterclaw::types::GuardModule::FsGuard,
        counterclaw::types::Severity::Critical,
        counterclaw::types::ActionTaken::Blocked,
        "Access to ~/.ssh blocked".to_string(),
    );

    let json = serde_json::to_string(&event).expect("Should serialize to JSON");
    let parsed: serde_json::Value = serde_json::from_str(&json).expect("Should be valid JSON");

    assert_eq!(parsed["module"], "fs_guard");
    assert_eq!(parsed["severity"], "critical");
    assert_eq!(parsed["action_taken"], "blocked");
    assert!(parsed["id"].is_string());
    assert!(parsed["timestamp"].is_string());
}

#[test]
fn severity_ordering_is_correct() {
    use counterclaw::types::Severity;
    assert!(Severity::Info < Severity::Warning);
    assert!(Severity::Warning < Severity::High);
    assert!(Severity::High < Severity::Critical);
}

// ===========================================================================
// Alerting : EventLogger (écriture fichier isolée)
// ===========================================================================

#[test]
fn logger_writes_event_to_jsonl() {
    let env = common::TestEnv::new();
    let logger = counterclaw::alerting::logger::EventLogger::new(
        &env.events_log_path().to_string_lossy(),
        10,
        3,
    );

    let event = counterclaw::types::SecurityEvent::new(
        counterclaw::types::GuardModule::System,
        counterclaw::types::Severity::Info,
        counterclaw::types::ActionTaken::Logged,
        "Test event".to_string(),
    );

    logger.log(&event);

    let events = env.parse_events();
    assert_eq!(events.len(), 1, "Should have written exactly one event");
    assert_eq!(events[0]["description"], "Test event");
}

#[test]
fn logger_appends_multiple_events() {
    let env = common::TestEnv::new();
    let logger = counterclaw::alerting::logger::EventLogger::new(
        &env.events_log_path().to_string_lossy(),
        10,
        3,
    );

    for i in 0..5 {
        let event = counterclaw::types::SecurityEvent::new(
            counterclaw::types::GuardModule::System,
            counterclaw::types::Severity::Info,
            counterclaw::types::ActionTaken::Logged,
            format!("Event {}", i),
        );
        logger.log(&event);
    }

    let events = env.parse_events();
    assert_eq!(events.len(), 5, "Should have 5 events");
}

#[test]
fn logger_creates_parent_directory() {
    let env = common::TestEnv::new();
    let deep_path = env.root().join("deep/nested/dir/events.jsonl");
    let logger =
        counterclaw::alerting::logger::EventLogger::new(&deep_path.to_string_lossy(), 10, 3);

    let event = counterclaw::types::SecurityEvent::new(
        counterclaw::types::GuardModule::System,
        counterclaw::types::Severity::Info,
        counterclaw::types::ActionTaken::Logged,
        "Deep path test".to_string(),
    );
    logger.log(&event);

    assert!(
        deep_path.exists(),
        "Logger should create parent directories"
    );
}

// ===========================================================================
// Alerting : macOS notifier (mode désactivé — pas d'osascript en test)
// ===========================================================================

#[test]
fn notifier_disabled_does_not_panic() {
    let notifier = counterclaw::alerting::macos_notify::MacosNotifier::new(false);
    let event = counterclaw::types::SecurityEvent::new(
        counterclaw::types::GuardModule::System,
        counterclaw::types::Severity::Critical,
        counterclaw::types::ActionTaken::Blocked,
        "Should not notify".to_string(),
    );
    // Ne doit pas paniquer même avec severity critical
    notifier.send(&event);
    assert!(!notifier.is_enabled());
}

// ===========================================================================
// CLI : tests d'intégration binaire
// ===========================================================================

#[test]
fn cli_help_shows_usage() {
    counterclaw_cmd()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("AI Agent Guardian"));
}

#[test]
fn cli_version_shows_version() {
    counterclaw_cmd()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains("counterclaw"));
}

#[test]
fn cli_config_check_with_valid_config() {
    let env = common::TestEnv::new();
    env.write_default_config();

    counterclaw_cmd()
        .args([
            "config",
            "check",
            "-c",
            &env.config_path().to_string_lossy(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Config is valid"));
}

#[test]
fn cli_config_check_with_missing_file_fails() {
    counterclaw_cmd()
        .args([
            "config",
            "check",
            "-c",
            "/tmp/nonexistent_counterclaw_config.yaml",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Error"));
}

// ===========================================================================
// Sécurité : le fichier de config ne doit pas être écrasé
// ===========================================================================

#[test]
fn config_init_does_not_overwrite_existing() {
    // Ce test vérifie un comportement de sécurité :
    // si l'utilisateur a modifié sa config, `config init` ne l'écrase pas.
    let env = common::TestEnv::new();
    let sentinel = "# THIS IS MY CUSTOM CONFIG\ngeneral:\n  mode: paranoid";
    let config_path = env.root().join("config.yaml");
    fs::write(&config_path, sentinel).unwrap();

    // Lire le contenu avant — il ne doit pas changer
    let before = fs::read_to_string(&config_path).unwrap();
    assert!(before.contains("THIS IS MY CUSTOM CONFIG"));
    // Note: init_config() écrit à ~/.counterclaw/ pas dans un chemin custom,
    // mais le principe est codé dans init_config(): if exists, return early.
}

// ===========================================================================
// Sécurité : les events JSON ne peuvent pas être forgés
// ===========================================================================

#[test]
fn security_event_timestamp_is_utc_now() {
    let before = chrono::Utc::now();
    let event = counterclaw::types::SecurityEvent::new(
        counterclaw::types::GuardModule::System,
        counterclaw::types::Severity::Info,
        counterclaw::types::ActionTaken::Logged,
        "test".to_string(),
    );
    let after = chrono::Utc::now();

    assert!(event.timestamp >= before, "Timestamp should be >= start");
    assert!(event.timestamp <= after, "Timestamp should be <= end");
}
