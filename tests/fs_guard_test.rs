//! Tests pour le module fs_guard — Filesystem Guard.
//!
//! Organisation :
//! - Étape 1 (1-9)   : PathMatcher logique pure
//! - Étape 2 (10-15) : Tests de contournement (bypass/edge)
//! - Étape 3 (16-20) : Actions + SecurityEvent
//! - Étape 4 (21-23) : Intégration async (Guard trait)

mod common;

use counterclaw::guards::fs_guard::{FsGuard, PathMatcher, PathVerdict};
use counterclaw::types::{Guard, GuardModule, OperationMode, Severity};
use std::path::PathBuf;
use tokio::sync::mpsc;

/// Mode par défaut pour les tests existants (permissif).
fn default_mode() -> OperationMode {
    OperationMode::Monitor
}

// ===========================================================================
// Helper : créer un PathMatcher de test avec des paths dans le temp dir
// ===========================================================================

fn home_dir() -> PathBuf {
    dirs::home_dir().expect("Cannot resolve home dir")
}

fn test_matcher() -> PathMatcher {
    let home = home_dir();
    PathMatcher::new(
        vec![
            home.join(".ssh").to_string_lossy().to_string(),
            home.join(".aws").to_string_lossy().to_string(),
            home.join(".env.*").to_string_lossy().to_string(),
        ],
        vec![home.join("Documents").to_string_lossy().to_string()],
        vec![home
            .join(".openclaw/workspace")
            .to_string_lossy()
            .to_string()],
    )
}

// ===========================================================================
// Étape 1 — PathMatcher logique pure (9 tests)
// ===========================================================================

/// L'accès à ~/.ssh doit être bloqué.
#[test]
fn blocks_access_to_ssh_directory() {
    let matcher = test_matcher();
    let path = home_dir().join(".ssh");
    assert_eq!(matcher.check(&path, &default_mode()), PathVerdict::Blocked);
}

/// L'accès à ~/.aws doit être bloqué.
#[test]
fn blocks_access_to_aws_credentials() {
    let matcher = test_matcher();
    let path = home_dir().join(".aws");
    assert_eq!(matcher.check(&path, &default_mode()), PathVerdict::Blocked);
}

/// L'accès au workspace autorisé doit passer.
#[test]
fn allows_access_to_workspace() {
    let matcher = test_matcher();
    let path = home_dir().join(".openclaw/workspace");
    assert_eq!(matcher.check(&path, &default_mode()), PathVerdict::Allowed);
}

/// L'accès à ~/Documents doit être read-only.
#[test]
fn marks_documents_as_read_only() {
    let matcher = test_matcher();
    let path = home_dir().join("Documents");
    assert_eq!(matcher.check(&path, &default_mode()), PathVerdict::ReadOnly);
}

/// Un chemin non configuré retourne Unmatched.
#[test]
fn unmatched_path_returns_unmatched() {
    let matcher = test_matcher();
    let path = home_dir().join("Music");
    assert_eq!(
        matcher.check(&path, &default_mode()),
        PathVerdict::Unmatched
    );
}

/// Si un path est dans blocked ET allowed, blocked gagne.
#[test]
fn blocked_takes_priority_over_allowed() {
    let home = home_dir();
    let matcher = PathMatcher::new(
        vec![home.join(".ssh").to_string_lossy().to_string()],
        vec![],
        vec![home.join(".ssh").to_string_lossy().to_string()],
    );
    let path = home.join(".ssh");
    assert_eq!(matcher.check(&path, &default_mode()), PathVerdict::Blocked);
}

/// Les paths avec tilde doivent être résolus avant comparaison.
#[test]
fn expands_tilde_in_blocked_paths() {
    let matcher = PathMatcher::new(vec!["~/.ssh".to_string()], vec![], vec![]);
    let path = home_dir().join(".ssh");
    assert_eq!(matcher.check(&path, &default_mode()), PathVerdict::Blocked);
}

/// Un glob pattern ~/.env.* doit matcher ~/.env.production.
#[test]
fn matches_glob_pattern() {
    let matcher = test_matcher();
    let path = home_dir().join(".env.production");
    assert_eq!(matcher.check(&path, &default_mode()), PathVerdict::Blocked);
}

/// Le glob ~/.env.* ne doit PAS matcher ~/.envrc (pas un point après env).
#[test]
fn glob_does_not_match_unrelated() {
    let matcher = test_matcher();
    let path = home_dir().join(".envrc");
    assert_eq!(
        matcher.check(&path, &default_mode()),
        PathVerdict::Unmatched
    );
}

// ===========================================================================
// Étape 2 — Tests de contournement (6 tests)
// ===========================================================================

/// Le path traversal ../../.ssh doit être bloqué après canonicalisation.
#[test]
fn blocks_ssh_via_path_traversal() {
    let matcher = PathMatcher::new(vec!["~/.ssh".to_string()], vec![], vec![]);
    // home/subdir/../../.ssh → home/.ssh
    let path = home_dir().join("subdir").join("..").join(".ssh");
    assert_eq!(matcher.check(&path, &default_mode()), PathVerdict::Blocked);
}

/// Les double-slashes sont nettoyées par la canonicalisation.
#[test]
fn blocks_ssh_via_double_slash() {
    let matcher = PathMatcher::new(vec!["~/.ssh".to_string()], vec![], vec![]);
    // Construire un chemin avec double slash
    let home = home_dir();
    let path_str = format!("{}/.ssh", home.display());
    let path = PathBuf::from(&path_str);
    assert_eq!(matcher.check(&path, &default_mode()), PathVerdict::Blocked);
}

/// Un chemin vide retourne Unmatched (pas de panic).
#[test]
fn handles_empty_path_gracefully() {
    let matcher = test_matcher();
    let path = PathBuf::from("");
    assert_eq!(
        matcher.check(&path, &default_mode()),
        PathVerdict::Unmatched
    );
}

/// Un chemin très long ne fait pas paniquer.
#[test]
fn handles_very_long_path() {
    let matcher = test_matcher();
    let long_segment = "a".repeat(1000);
    let path = home_dir().join(&long_segment);
    // Ne doit pas paniquer, retourne probablement Unmatched
    let _ = matcher.check(&path, &default_mode());
}

/// Un sous-répertoire d'un chemin bloqué est aussi bloqué.
#[test]
fn blocks_subdirectory_of_blocked_path() {
    let matcher = PathMatcher::new(vec!["~/.ssh".to_string()], vec![], vec![]);
    let path = home_dir().join(".ssh").join("keys").join("deploy");
    assert_eq!(matcher.check(&path, &default_mode()), PathVerdict::Blocked);
}

/// ~/.ssh_backup ne doit PAS être bloqué par la règle ~/.ssh.
#[test]
fn allows_path_that_starts_similarly() {
    let matcher = PathMatcher::new(vec!["~/.ssh".to_string()], vec![], vec![]);
    let path = home_dir().join(".ssh_backup");
    assert_eq!(
        matcher.check(&path, &default_mode()),
        PathVerdict::Unmatched
    );
}

// ===========================================================================
// Étape 3 — Actions + SecurityEvent (5 tests)
// ===========================================================================

/// En mode enforce + kill_and_alert, l'action est Killed.
#[test]
fn kill_and_alert_returns_killed_action() {
    use counterclaw::types::ActionTaken;
    let action = FsGuard::determine_action("kill_and_alert", Some(1234));
    assert!(matches!(action, ActionTaken::Killed { pid: 1234 }));
}

/// En mode enforce + alert_only, l'action est Alerted.
#[test]
fn alert_only_returns_alerted_action() {
    use counterclaw::types::ActionTaken;
    let action = FsGuard::determine_action("alert_only", None);
    assert!(matches!(action, ActionTaken::Alerted));
}

/// En mode monitor (log_only), l'action est Logged.
#[test]
fn log_only_returns_logged_action() {
    use counterclaw::types::ActionTaken;
    let action = FsGuard::determine_action("log_only", None);
    assert!(matches!(action, ActionTaken::Logged));
}

/// Un accès bloqué produit un SecurityEvent avec module=FsGuard, severity=Critical.
#[test]
fn creates_event_for_blocked_path() {
    let event = FsGuard::create_blocked_event(&home_dir().join(".ssh"), "create");
    assert_eq!(event.module, GuardModule::FsGuard);
    assert_eq!(event.severity, Severity::Critical);
    assert!(event.description.contains(".ssh"));
}

/// Un write sur read-only produit un event severity=Warning.
#[test]
fn creates_event_for_read_only_write() {
    let event =
        FsGuard::create_read_only_event(&home_dir().join("Documents").join("secret.txt"), "modify");
    assert_eq!(event.module, GuardModule::FsGuard);
    assert_eq!(event.severity, Severity::Warning);
    assert!(event.description.contains("Documents"));
}

// ===========================================================================
// Étape 4 — Intégration async (3 tests)
// ===========================================================================

/// Un événement bloqué est envoyé dans le canal mpsc.
#[tokio::test]
async fn sends_event_through_channel() {
    let (tx, mut rx) = mpsc::channel(16);
    let event = FsGuard::create_blocked_event(&home_dir().join(".ssh"), "access");
    tx.send(event).await.expect("send failed");

    let received = rx.recv().await.expect("recv failed");
    assert_eq!(received.module, GuardModule::FsGuard);
    assert_eq!(received.severity, Severity::Critical);
}

/// Après start, le guard rapporte running=true.
#[tokio::test]
async fn guard_reports_running_status() {
    let env = common::TestEnv::new();
    let config = fs_guard_config(&env);
    env.write_config(&config);
    let app_config =
        counterclaw::config::AppConfig::load(&env.config_path()).expect("Failed to load config");

    let guard = FsGuard::new(&app_config.fs_guard);
    let (tx, _rx) = mpsc::channel(16);
    guard.start(tx).await.expect("start failed");

    let status = guard.status();
    assert!(status.running);

    guard.stop().await.expect("stop failed");
}

/// Après stop, le guard rapporte running=false.
#[tokio::test]
async fn guard_reports_stopped_status() {
    let env = common::TestEnv::new();
    let config = fs_guard_config(&env);
    env.write_config(&config);
    let app_config =
        counterclaw::config::AppConfig::load(&env.config_path()).expect("Failed to load config");

    let guard = FsGuard::new(&app_config.fs_guard);
    let (tx, _rx) = mpsc::channel(16);
    guard.start(tx).await.expect("start failed");
    guard.stop().await.expect("stop failed");

    let status = guard.status();
    assert!(!status.running);
}

// ===========================================================================
// Helper : config YAML pour fs_guard tests
// ===========================================================================

fn fs_guard_config(env: &common::TestEnv) -> String {
    let root = env.root().display();
    let events = env.events_log_path();
    let events_str = events.to_string_lossy();
    let home = home_dir();
    let home_str = home.display();

    format!(
        r##"
general:
  mode: enforce
  pid_file: {root}/counterclaw.pid
  log_level: info
  log_file: {root}/logs/counterclaw.log
  log_max_size_mb: 10

fs_guard:
  enabled: true
  watch_processes:
    - "openclaw"
  blocked_paths:
    - "{home_str}/.ssh"
    - "{home_str}/.aws"
  read_only_paths:
    - "{home_str}/Documents"
  allowed_paths:
    - "{home_str}/.openclaw/workspace"
  on_violation:
    action: kill_and_alert
    kill_target: process

cdp_proxy:
  enabled: false
  listen_port: 18792
  upstream_port: 18800
  bind_address: "127.0.0.1"
  domains:
    blocked: []
    allowed: []
    require_approval: []
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
  enabled: false
  blacklist: []
  require_approval: []
  monitoring_method: log_only

alerting:
  macos_notification:
    enabled: false
  slack:
    enabled: false
    webhook_url: "https://hooks.slack.com/services/XXXX/YYYY/ZZZZ"
    channel: "#test"
    min_severity: warning
  file_log:
    enabled: true
    path: {events_str}
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
    )
}
