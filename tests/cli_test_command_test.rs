//! Tests pour la commande CLI `counterclaw test path|domain|command`.
//!
//! Valide que la commande test charge la config, instancie les matchers,
//! et retourne le bon verdict + exit code.

mod common;

use predicates::prelude::*;

/// Helper pour creer une commande pointant vers le binaire compile.
#[allow(deprecated)]
fn counterclaw_cmd() -> assert_cmd::Command {
    assert_cmd::Command::cargo_bin("counterclaw").unwrap()
}

/// Ecrit une config avec des regles specifiques pour les tests CLI.
fn write_test_rules_config(env: &common::TestEnv) {
    let root = env.root().display();
    let events_path = env.events_log_path().to_string_lossy().to_string();

    let yaml = format!(
        r##"
general:
  mode: monitor
  pid_file: {root}/counterclaw.pid
  log_level: info
  log_file: {root}/logs/counterclaw.log
  log_max_size_mb: 10

fs_guard:
  enabled: true
  watch_processes: []
  blocked_paths:
    - "~/.ssh"
    - "~/.aws"
  read_only_paths:
    - "~/Documents"
  allowed_paths:
    - "/tmp/safe"
  on_violation:
    action: log_only
    kill_target: process

cdp_proxy:
  enabled: true
  listen_port: 18792
  upstream_port: 18800
  bind_address: "127.0.0.1"
  domains:
    blocked:
      - "evil.com"
      - "malware.org"
    allowed:
      - "github.com"
      - "stackoverflow.com"
    require_approval:
      - "amazon.com"
    default_policy: allow
  cdp_commands:
    blocked: []
    restricted_to_allowed_domains: []
    log_always: []
  content_inspection:
    enabled: false
    patterns: []

net_guard:
  enabled: false
  watch_processes: []
  allowed_egress: []
  max_post_payload_bytes: 51200
  block_unknown_post: false
  alert_on_unknown_dns: false
  enforcement_method: log_only

cmd_guard:
  enabled: true
  blacklist:
    - pattern: 'rm\s+-rf\s+/'
      description: "Recursive delete from root"
      severity: critical
    - pattern: 'curl\s+.*\|\s*(ba)?sh'
      description: "Download and execute"
      severity: critical
  require_approval:
    - pattern: 'pip\s+install'
      description: "Python package install"
  monitoring_method: log_only

alerting:
  macos_notification:
    enabled: false
  slack:
    enabled: false
    webhook_url: "https://hooks.slack.com/test"
    channel: "#test"
    min_severity: warning
  file_log:
    enabled: true
    path: {events_path}
    max_size_mb: 10
    keep_files: 3
  kill_switch:
    enabled: false
    threshold_severity: warning
    threshold_count: 3
    threshold_window_seconds: 60
    action: alert_only

dashboard:
  enabled: false
  bind_address: "127.0.0.1"
  port: 9999
"##
    );
    env.write_config(&yaml);
}

// ===========================================================================
// Path tests
// ===========================================================================

#[test]
fn cli_test_path_blocked_exits_1() {
    let env = common::TestEnv::new();
    write_test_rules_config(&env);

    counterclaw_cmd()
        .args([
            "test",
            "-c",
            &env.config_path().to_string_lossy(),
            "path",
            "~/.ssh/id_rsa",
        ])
        .assert()
        .failure();
}

#[test]
fn cli_test_path_blocked_shows_verdict() {
    let env = common::TestEnv::new();
    write_test_rules_config(&env);

    counterclaw_cmd()
        .args([
            "test",
            "-c",
            &env.config_path().to_string_lossy(),
            "path",
            "~/.ssh",
        ])
        .assert()
        .failure()
        .stdout(predicate::str::contains("BLOCKED"));
}

#[test]
fn cli_test_path_allowed_exits_0() {
    let env = common::TestEnv::new();
    write_test_rules_config(&env);

    counterclaw_cmd()
        .args([
            "test",
            "-c",
            &env.config_path().to_string_lossy(),
            "path",
            "/tmp/safe/file.txt",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("ALLOWED"));
}

#[test]
fn cli_test_path_unmatched_exits_0() {
    let env = common::TestEnv::new();
    write_test_rules_config(&env);

    counterclaw_cmd()
        .args([
            "test",
            "-c",
            &env.config_path().to_string_lossy(),
            "path",
            "/usr/local/bin/something",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("UNMATCHED"));
}

// ===========================================================================
// Domain tests
// ===========================================================================

#[test]
fn cli_test_domain_blocked_exits_1() {
    let env = common::TestEnv::new();
    write_test_rules_config(&env);

    counterclaw_cmd()
        .args([
            "test",
            "-c",
            &env.config_path().to_string_lossy(),
            "domain",
            "evil.com",
        ])
        .assert()
        .failure()
        .stdout(predicate::str::contains("BLOCKED"));
}

#[test]
fn cli_test_domain_allowed_exits_0() {
    let env = common::TestEnv::new();
    write_test_rules_config(&env);

    counterclaw_cmd()
        .args([
            "test",
            "-c",
            &env.config_path().to_string_lossy(),
            "domain",
            "github.com",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("ALLOWED"));
}

#[test]
fn cli_test_domain_approval_shows_info() {
    let env = common::TestEnv::new();
    write_test_rules_config(&env);

    counterclaw_cmd()
        .args([
            "test",
            "-c",
            &env.config_path().to_string_lossy(),
            "domain",
            "amazon.com",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("REQUIRE_APPROVAL"));
}

// ===========================================================================
// Command tests
// ===========================================================================

#[test]
fn cli_test_command_blocked_exits_1() {
    let env = common::TestEnv::new();
    write_test_rules_config(&env);

    counterclaw_cmd()
        .args([
            "test",
            "-c",
            &env.config_path().to_string_lossy(),
            "command",
            "rm -rf /",
        ])
        .assert()
        .failure()
        .stdout(predicate::str::contains("BLOCKED"));
}

#[test]
fn cli_test_command_shows_severity() {
    let env = common::TestEnv::new();
    write_test_rules_config(&env);

    counterclaw_cmd()
        .args([
            "test",
            "-c",
            &env.config_path().to_string_lossy(),
            "command",
            "rm -rf /",
        ])
        .assert()
        .failure()
        .stdout(predicate::str::contains("CRIT"));
}

#[test]
fn cli_test_command_safe_exits_0() {
    let env = common::TestEnv::new();
    write_test_rules_config(&env);

    counterclaw_cmd()
        .args([
            "test",
            "-c",
            &env.config_path().to_string_lossy(),
            "command",
            "cargo build",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("ALLOWED"));
}

// ===========================================================================
// Config & edge case tests
// ===========================================================================

#[test]
fn cli_test_with_custom_config() {
    let env = common::TestEnv::new();
    write_test_rules_config(&env);

    // Verify --config / -c works
    counterclaw_cmd()
        .args([
            "test",
            "-c",
            &env.config_path().to_string_lossy(),
            "domain",
            "github.com",
        ])
        .assert()
        .success();
}

#[test]
fn cli_test_missing_config_fails() {
    counterclaw_cmd()
        .args([
            "test",
            "-c",
            "/tmp/nonexistent_counterclaw_test.yaml",
            "path",
            "/tmp",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Error"));
}

#[test]
fn cli_test_path_empty_graceful() {
    let env = common::TestEnv::new();
    write_test_rules_config(&env);

    counterclaw_cmd()
        .args([
            "test",
            "-c",
            &env.config_path().to_string_lossy(),
            "path",
            "",
        ])
        .assert()
        .success() // empty path = unmatched = exit 0
        .stdout(predicate::str::contains("UNMATCHED"));
}

#[test]
fn cli_test_command_empty_graceful() {
    let env = common::TestEnv::new();
    write_test_rules_config(&env);

    counterclaw_cmd()
        .args([
            "test",
            "-c",
            &env.config_path().to_string_lossy(),
            "command",
            "",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("ALLOWED"));
}

#[test]
fn cli_test_help_shows_test() {
    counterclaw_cmd()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("test"));
}
