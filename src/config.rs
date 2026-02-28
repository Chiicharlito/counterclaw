//! Chargement, validation et initialisation de la configuration YAML.
//!
//! Le fichier de config vit dans `~/.counterclaw/config.yaml`.
//! Ce module est responsable de :
//! - parser le YAML en structs Rust typées
//! - valider la cohérence (ports, paths, modes)
//! - créer une config par défaut avec `config init`
//! - résoudre les `~` en chemin absolu

use crate::types::CounterClawError;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// Expansion du tilde (~) vers le répertoire home
// ---------------------------------------------------------------------------

/// Résout `~` au début d'un chemin vers le répertoire home de l'utilisateur.
pub fn expand_tilde(path: &str) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/") {
        if let Some(home) = dirs::home_dir() {
            return home.join(rest);
        }
    } else if path == "~" {
        if let Some(home) = dirs::home_dir() {
            return home;
        }
    }
    PathBuf::from(path)
}

/// Chemin par défaut du fichier de configuration.
pub fn default_config_path() -> PathBuf {
    expand_tilde("~/.counterclaw/config.yaml")
}

/// Chemin par défaut du répertoire CounterClaw.
pub fn counterclaw_dir() -> PathBuf {
    expand_tilde("~/.counterclaw")
}

// ---------------------------------------------------------------------------
// Structures de configuration — miroir exact du YAML
// ---------------------------------------------------------------------------

/// Configuration racine de CounterClaw.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    pub general: GeneralConfig,
    pub fs_guard: FsGuardConfig,
    pub cdp_proxy: CdpProxyConfig,
    pub net_guard: NetGuardConfig,
    pub cmd_guard: CmdGuardConfig,
    pub alerting: AlertingConfig,
    pub dashboard: DashboardConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneralConfig {
    pub mode: String,
    pub pid_file: String,
    pub log_level: String,
    pub log_file: String,
    pub log_max_size_mb: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FsGuardConfig {
    pub enabled: bool,
    pub watch_processes: Vec<String>,
    pub blocked_paths: Vec<String>,
    pub read_only_paths: Vec<String>,
    pub allowed_paths: Vec<String>,
    pub on_violation: FsViolationConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FsViolationConfig {
    pub action: String,
    pub kill_target: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CdpProxyConfig {
    pub enabled: bool,
    pub listen_port: u16,
    pub upstream_port: u16,
    pub bind_address: String,
    pub domains: DomainRulesConfig,
    pub cdp_commands: CdpCommandsConfig,
    pub content_inspection: ContentInspectionConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainRulesConfig {
    pub blocked: Vec<String>,
    pub allowed: Vec<String>,
    pub require_approval: Vec<String>,
    pub default_policy: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CdpCommandsConfig {
    pub blocked: Vec<String>,
    pub restricted_to_allowed_domains: Vec<String>,
    pub log_always: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentInspectionConfig {
    pub enabled: bool,
    pub patterns: Vec<ContentPatternConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentPatternConfig {
    pub name: String,
    pub regex: String,
    pub severity: String,
    pub action: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetGuardConfig {
    pub enabled: bool,
    pub watch_processes: Vec<String>,
    pub allowed_egress: Vec<String>,
    pub max_post_payload_bytes: u64,
    pub block_unknown_post: bool,
    pub alert_on_unknown_dns: bool,
    pub enforcement_method: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CmdGuardConfig {
    pub enabled: bool,
    pub blacklist: Vec<CommandPatternConfig>,
    pub require_approval: Vec<ApprovalPatternConfig>,
    pub monitoring_method: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandPatternConfig {
    pub pattern: String,
    pub description: String,
    pub severity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalPatternConfig {
    pub pattern: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertingConfig {
    pub macos_notification: MacosNotificationConfig,
    pub slack: SlackConfig,
    pub file_log: FileLogConfig,
    pub kill_switch: KillSwitchConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MacosNotificationConfig {
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlackConfig {
    pub enabled: bool,
    pub webhook_url: String,
    pub channel: String,
    pub min_severity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileLogConfig {
    pub enabled: bool,
    pub path: String,
    pub max_size_mb: u64,
    pub keep_files: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KillSwitchConfig {
    pub enabled: bool,
    pub threshold_severity: String,
    pub threshold_count: u32,
    pub threshold_window_seconds: u64,
    pub action: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardConfig {
    pub enabled: bool,
    pub bind_address: String,
    pub port: u16,
}

// ---------------------------------------------------------------------------
// Chargement et validation
// ---------------------------------------------------------------------------

impl AppConfig {
    /// Charge la configuration depuis un fichier YAML.
    pub fn load(path: &Path) -> Result<Self, CounterClawError> {
        let content = std::fs::read_to_string(path).map_err(|e| CounterClawError::ConfigLoad {
            path: path.display().to_string(),
            source: Box::new(e),
        })?;

        let config: AppConfig =
            serde_yaml::from_str(&content).map_err(|e| CounterClawError::ConfigLoad {
                path: path.display().to_string(),
                source: Box::new(e),
            })?;

        Ok(config)
    }

    /// Valide la configuration et retourne une liste d'erreurs (vide = OK).
    pub fn validate(&self) -> Vec<String> {
        let mut errors = Vec::new();

        // Mode valide ?
        let valid_modes = ["monitor", "enforce", "paranoid"];
        if !valid_modes.contains(&self.general.mode.as_str()) {
            errors.push(format!(
                "general.mode '{}' is invalid (expected: monitor, enforce, paranoid)",
                self.general.mode
            ));
        }

        // Log level valide ?
        let valid_levels = ["trace", "debug", "info", "warn", "error"];
        if !valid_levels.contains(&self.general.log_level.as_str()) {
            errors.push(format!(
                "general.log_level '{}' is invalid (expected: trace, debug, info, warn, error)",
                self.general.log_level
            ));
        }

        // Ports CDP dans une plage raisonnable
        if self.cdp_proxy.enabled && self.cdp_proxy.listen_port == self.cdp_proxy.upstream_port {
            errors.push("cdp_proxy.listen_port and upstream_port must be different".to_string());
        }

        // Vérifier que les severities sont valides partout
        let valid_severities = ["info", "warning", "high", "critical"];

        if !valid_severities.contains(&self.alerting.slack.min_severity.as_str()) {
            errors.push(format!(
                "alerting.slack.min_severity '{}' is invalid",
                self.alerting.slack.min_severity
            ));
        }

        if !valid_severities.contains(&self.alerting.kill_switch.threshold_severity.as_str()) {
            errors.push(format!(
                "alerting.kill_switch.threshold_severity '{}' is invalid",
                self.alerting.kill_switch.threshold_severity
            ));
        }

        // Vérifier les regex des content patterns
        for pattern in &self.cdp_proxy.content_inspection.patterns {
            if regex::Regex::new(&pattern.regex).is_err() {
                errors.push(format!(
                    "cdp_proxy.content_inspection.patterns[{}].regex is invalid",
                    pattern.name
                ));
            }
        }

        // Vérifier les regex des blacklist commands
        for cmd in &self.cmd_guard.blacklist {
            if regex::Regex::new(&cmd.pattern).is_err() {
                errors.push(format!(
                    "cmd_guard.blacklist pattern '{}' is invalid regex",
                    cmd.pattern
                ));
            }
        }

        // Dashboard port
        if self.dashboard.enabled && self.dashboard.port == 0 {
            errors.push("dashboard.port cannot be 0".to_string());
        }

        // Au moins un backend d'alerting activé
        if !self.alerting.file_log.enabled
            && !self.alerting.macos_notification.enabled
            && !self.alerting.slack.enabled
        {
            errors.push("At least one alerting backend should be enabled".to_string());
        }

        errors
    }

    /// Retourne le mode d'opération parsé.
    pub fn operation_mode(&self) -> crate::types::OperationMode {
        match self.general.mode.as_str() {
            "enforce" => crate::types::OperationMode::Enforce,
            "paranoid" => crate::types::OperationMode::Paranoid,
            _ => crate::types::OperationMode::Monitor,
        }
    }

    /// Retourne le chemin résolu (avec tilde expandé) du fichier de log events.
    #[allow(dead_code)]
    pub fn events_log_path(&self) -> PathBuf {
        expand_tilde(&self.alerting.file_log.path)
    }

    /// Sauvegarde la configuration dans un fichier YAML.
    pub fn save(&self, path: &Path) -> Result<(), CounterClawError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                CounterClawError::Config(format!(
                    "Cannot create directory {}: {}",
                    parent.display(),
                    e
                ))
            })?;
        }
        let yaml = serde_yaml::to_string(self)
            .map_err(|e| CounterClawError::Config(format!("Failed to serialize config: {}", e)))?;
        std::fs::write(path, yaml).map_err(|e| {
            CounterClawError::Config(format!("Cannot write config to {}: {}", path.display(), e))
        })?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Initialisation : créer le fichier de config par défaut
// ---------------------------------------------------------------------------

/// Crée le répertoire `~/.counterclaw/` et copie la config exemple dedans.
/// Ne fait rien si le fichier existe déjà.
pub fn init_config() -> Result<PathBuf, CounterClawError> {
    let config_dir = counterclaw_dir();
    let config_path = default_config_path();
    let logs_dir = config_dir.join("logs");

    // Créer les répertoires
    std::fs::create_dir_all(&logs_dir).map_err(|e| {
        CounterClawError::Config(format!(
            "Cannot create directory {}: {}",
            logs_dir.display(),
            e
        ))
    })?;

    // Ne pas écraser un fichier existant
    if config_path.exists() {
        return Ok(config_path);
    }

    // Écrire la config par défaut
    let default_yaml = include_str!("../counterclaw.example.yaml");
    std::fs::write(&config_path, default_yaml).map_err(|e| {
        CounterClawError::Config(format!(
            "Cannot write config to {}: {}",
            config_path.display(),
            e
        ))
    })?;

    Ok(config_path)
}

/// Charge et valide la config, affiche les erreurs.
/// Retourne Ok(config) si valide, Err sinon.
pub fn check_config(path: &Path) -> Result<AppConfig, CounterClawError> {
    let config = AppConfig::load(path)?;
    let errors = config.validate();

    if errors.is_empty() {
        Ok(config)
    } else {
        let msg = errors
            .iter()
            .enumerate()
            .map(|(i, e)| format!("  {}. {}", i + 1, e))
            .collect::<Vec<_>>()
            .join("\n");
        Err(CounterClawError::Config(format!(
            "Config validation failed:\n{}",
            msg
        )))
    }
}
