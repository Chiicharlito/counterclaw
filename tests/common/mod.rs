//! Helpers partagés pour les tests d'intégration.
//!
//! Chaque test utilise un répertoire temporaire isolé.
//! Aucun test ne touche ~/.counterclaw/ (le vrai répertoire).

// Each test file is compiled independently and may not use every helper.
#![allow(dead_code)]

use std::fs;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

// ---------------------------------------------------------------------------
// Environnement de test isolé
// ---------------------------------------------------------------------------

/// Un environnement de test avec son propre répertoire temp,
/// sa propre config, et son propre répertoire de logs.
/// Tout est nettoyé automatiquement quand le TestEnv est droppé.
pub struct TestEnv {
    /// Répertoire temporaire — gardé vivant pour la durée du test.
    /// Le drop de TempDir supprime le répertoire.
    pub dir: TempDir,
}

impl TestEnv {
    /// Crée un nouvel environnement de test isolé.
    pub fn new() -> Self {
        let dir = TempDir::new().expect("Failed to create temp dir");
        fs::create_dir_all(dir.path().join("logs")).expect("Failed to create logs dir");
        Self { dir }
    }

    /// Chemin du répertoire racine.
    pub fn root(&self) -> &Path {
        self.dir.path()
    }

    /// Chemin du fichier de config.
    pub fn config_path(&self) -> PathBuf {
        self.dir.path().join("config.yaml")
    }

    /// Chemin du fichier de log events.
    pub fn events_log_path(&self) -> PathBuf {
        self.dir.path().join("logs").join("events.jsonl")
    }

    /// Écrit une config YAML dans le répertoire temp.
    pub fn write_config(&self, yaml: &str) {
        fs::write(self.config_path(), yaml).expect("Failed to write config");
    }

    /// Écrit la config par défaut (mode monitor) dans le répertoire temp.
    /// Remplace les chemins ~ par le répertoire temp.
    pub fn write_default_config(&self) {
        let default = include_str!("../../counterclaw.example.yaml");
        let patched = default
            .replace(
                "~/.counterclaw/logs/events.jsonl",
                &self.events_log_path().to_string_lossy(),
            )
            .replace(
                "~/.counterclaw/counterclaw.pid",
                &self.dir.path().join("counterclaw.pid").to_string_lossy(),
            )
            .replace(
                "~/.counterclaw/logs/counterclaw.log",
                &self
                    .dir
                    .path()
                    .join("logs/counterclaw.log")
                    .to_string_lossy(),
            );
        fs::write(self.config_path(), patched).expect("Failed to write default config");
    }

    /// Lit le contenu du fichier de log events.
    pub fn read_events_log(&self) -> String {
        let path = self.events_log_path();
        if path.exists() {
            fs::read_to_string(&path).expect("Failed to read events log")
        } else {
            String::new()
        }
    }

    /// Parse les events JSON du fichier de log.
    pub fn parse_events(&self) -> Vec<serde_json::Value> {
        self.read_events_log()
            .lines()
            .filter(|line| !line.is_empty())
            .map(|line| serde_json::from_str(line).expect("Invalid JSON in events log"))
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Configs YAML de test — configs minimales pour différents scénarios
// ---------------------------------------------------------------------------

/// Config minimale valide en mode monitor.
pub fn minimal_monitor_config(env: &TestEnv) -> String {
    let root = env.root().display();
    let events_path = env.events_log_path();
    let events_str = events_path.to_string_lossy();

    let mut yaml = String::from(VALID_CONFIG_TEMPLATE);
    yaml = yaml.replace("ROOT_PLACEHOLDER", &root.to_string());
    yaml = yaml.replace("EVENTS_PATH_PLACEHOLDER", &events_str);
    yaml
}

const VALID_CONFIG_TEMPLATE: &str = r##"
general:
  mode: monitor
  pid_file: ROOT_PLACEHOLDER/counterclaw.pid
  log_level: info
  log_file: ROOT_PLACEHOLDER/logs/counterclaw.log
  log_max_size_mb: 10

fs_guard:
  enabled: false
  watch_processes: []
  blocked_paths: []
  read_only_paths: []
  allowed_paths: []
  on_violation:
    action: log_only
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
    path: EVENTS_PATH_PLACEHOLDER
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
"##;

/// Trouve un port TCP libre en bindant sur le port 0.
pub fn find_free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("Failed to bind to port 0");
    listener.local_addr().unwrap().port()
}

/// Config avec des valeurs invalides — pour tester la validation.
pub fn invalid_config() -> &'static str {
    r##"
general:
  mode: INVALID_MODE
  pid_file: /tmp/test.pid
  log_level: INVALID_LEVEL
  log_file: /tmp/test.log
  log_max_size_mb: 10

fs_guard:
  enabled: false
  watch_processes: []
  blocked_paths: []
  read_only_paths: []
  allowed_paths: []
  on_violation:
    action: log_only
    kill_target: process

cdp_proxy:
  enabled: true
  listen_port: 18792
  upstream_port: 18792
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
    webhook_url: "https://example.com"
    channel: "#test"
    min_severity: INVALID_SEVERITY
  file_log:
    enabled: false
    path: /tmp/test.jsonl
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
}
