//! Types partagés entre tous les modules de CounterClaw.
//!
//! Ce fichier définit le vocabulaire commun du projet :
//! les événements de sécurité, les niveaux de gravité,
//! le trait Guard que chaque module implémente, et les erreurs typées.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::fmt;
use tokio::sync::mpsc;

// ---------------------------------------------------------------------------
// Enums fondamentaux
// ---------------------------------------------------------------------------

/// Niveau de gravité d'un événement de sécurité.
/// L'ordre est important : on compare les niveaux entre eux (Info < Warning < High < Critical).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Warning,
    High,
    Critical,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Info => write!(f, "INFO"),
            Severity::Warning => write!(f, "WARN"),
            Severity::High => write!(f, "HIGH"),
            Severity::Critical => write!(f, "CRIT"),
        }
    }
}

/// Quel module de garde a généré l'événement.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GuardModule {
    FsGuard,
    CdpProxy,
    NetGuard,
    CmdGuard,
    /// Pour les événements système (démarrage, arrêt, kill switch).
    System,
}

impl fmt::Display for GuardModule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GuardModule::FsGuard => write!(f, "fs_guard"),
            GuardModule::CdpProxy => write!(f, "cdp_proxy"),
            GuardModule::NetGuard => write!(f, "net_guard"),
            GuardModule::CmdGuard => write!(f, "cmd_guard"),
            GuardModule::System => write!(f, "system"),
        }
    }
}

/// Action prise par CounterClaw en réponse à un événement.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionTaken {
    Blocked,
    Killed { pid: u32 },
    Alerted,
    Logged,
    AwaitingApproval,
    Approved,
    Denied,
}

impl fmt::Display for ActionTaken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ActionTaken::Blocked => write!(f, "BLOCKED"),
            ActionTaken::Killed { pid } => write!(f, "KILLED(pid={})", pid),
            ActionTaken::Alerted => write!(f, "ALERTED"),
            ActionTaken::Logged => write!(f, "LOGGED"),
            ActionTaken::AwaitingApproval => write!(f, "AWAITING_APPROVAL"),
            ActionTaken::Approved => write!(f, "APPROVED"),
            ActionTaken::Denied => write!(f, "DENIED"),
        }
    }
}

/// Mode de fonctionnement global de CounterClaw.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum OperationMode {
    /// Log seulement, ne bloque rien (mode apprentissage).
    Monitor,
    /// Bloque activement les actions interdites.
    Enforce,
    /// Bloque tout ce qui n'est pas explicitement autorisé.
    Paranoid,
}

impl fmt::Display for OperationMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OperationMode::Monitor => write!(f, "monitor"),
            OperationMode::Enforce => write!(f, "enforce"),
            OperationMode::Paranoid => write!(f, "paranoid"),
        }
    }
}

// ---------------------------------------------------------------------------
// SecurityEvent — l'unité de base du système d'alerting
// ---------------------------------------------------------------------------

/// Événement de sécurité émis par n'importe quel module.
/// C'est la structure centrale qui transite dans le canal mpsc
/// entre les gardes et le moteur d'alerting.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub module: GuardModule,
    pub severity: Severity,
    pub action_taken: ActionTaken,
    pub description: String,
    pub details: serde_json::Value,
    pub process_info: Option<ProcessInfo>,
}

impl SecurityEvent {
    /// Crée un nouvel événement avec un UUID auto-généré et le timestamp courant.
    pub fn new(
        module: GuardModule,
        severity: Severity,
        action_taken: ActionTaken,
        description: String,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            module,
            severity,
            action_taken,
            description,
            details: serde_json::Value::Null,
            process_info: None,
        }
    }

    /// Attache des détails JSON à l'événement.
    #[allow(dead_code)]
    pub fn with_details(mut self, details: serde_json::Value) -> Self {
        self.details = details;
        self
    }

    /// Attache des informations sur le processus concerné.
    #[allow(dead_code)]
    pub fn with_process_info(mut self, info: ProcessInfo) -> Self {
        self.process_info = Some(info);
        self
    }
}

/// Informations sur un processus surveillé.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub cmd: String,
    pub parent_pid: Option<u32>,
}

// ---------------------------------------------------------------------------
// Guard trait — interface commune à tous les modules de surveillance
// ---------------------------------------------------------------------------

/// Status d'un module de garde.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct GuardStatus {
    pub running: bool,
    pub events_total: u64,
    pub events_blocked: u64,
    pub last_event: Option<DateTime<Utc>>,
    pub uptime: Duration,
}

/// Trait que chaque module de surveillance implémente.
/// Cela garantit une interface uniforme pour démarrer, arrêter
/// et interroger chaque garde.
#[async_trait::async_trait]
#[allow(dead_code)]
pub trait Guard: Send + Sync {
    /// Nom humain du module (ex: "fs_guard", "cdp_proxy").
    fn name(&self) -> &str;

    /// Démarre la surveillance. Le sender permet d'envoyer des événements
    /// au moteur d'alerting central.
    async fn start(&self, alert_tx: mpsc::Sender<SecurityEvent>) -> anyhow::Result<()>;

    /// Arrête proprement la surveillance.
    async fn stop(&self) -> anyhow::Result<()>;

    /// Retourne le status courant du module.
    fn status(&self) -> GuardStatus;
}

// ---------------------------------------------------------------------------
// Erreurs typées
// ---------------------------------------------------------------------------

/// Erreurs spécifiques à CounterClaw.
/// On utilise thiserror pour générer les implémentations Display/Error
/// automatiquement.
#[derive(Debug, thiserror::Error)]
pub enum CounterClawError {
    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Failed to load config from {path}: {source}")]
    ConfigLoad {
        path: String,
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    #[error("Guard module '{module}' failed: {reason}")]
    #[allow(dead_code)]
    GuardFailure { module: String, reason: String },

    #[error("Alerting error: {0}")]
    #[allow(dead_code)]
    Alerting(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

// ---------------------------------------------------------------------------
// EventBuffer — buffer circulaire pour le dashboard
// ---------------------------------------------------------------------------

/// Buffer circulaire d'événements de sécurité.
/// Évince les plus anciens quand la capacité est atteinte.
/// Utilisé par le dashboard pour exposer les événements récents via l'API.
pub struct EventBuffer {
    events: VecDeque<SecurityEvent>,
    max_capacity: usize,
}

impl EventBuffer {
    /// Crée un nouveau buffer avec la capacité maximale donnée.
    pub fn new(capacity: usize) -> Self {
        Self {
            events: VecDeque::with_capacity(capacity.min(1024)),
            max_capacity: capacity,
        }
    }

    /// Ajoute un événement. Évince le plus ancien si le buffer est plein.
    pub fn push(&mut self, event: SecurityEvent) {
        if self.events.len() >= self.max_capacity {
            self.events.pop_front();
        }
        self.events.push_back(event);
    }

    /// Retourne le nombre d'événements dans le buffer.
    pub fn len(&self) -> usize {
        self.events.len()
    }

    /// Retourne true si le buffer est vide.
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// Requête filtrée sur le buffer.
    /// - limit: nombre max de résultats (0 = pas de limite)
    /// - min_severity: filtre par sévérité minimale (None = pas de filtre)
    /// - module: filtre par module (None = pas de filtre)
    /// - since: filtre par timestamp (None = pas de filtre)
    pub fn query(
        &self,
        limit: usize,
        min_severity: Option<&Severity>,
        module: Option<&GuardModule>,
        since: Option<DateTime<Utc>>,
    ) -> Vec<&SecurityEvent> {
        let iter = self.events.iter().rev(); // Most recent first

        let filtered = iter.filter(|e| {
            if let Some(sev) = min_severity {
                if e.severity < *sev {
                    return false;
                }
            }
            if let Some(m) = module {
                if e.module != *m {
                    return false;
                }
            }
            if let Some(ts) = since {
                if e.timestamp < ts {
                    return false;
                }
            }
            true
        });

        if limit > 0 {
            filtered.take(limit).collect()
        } else {
            filtered.collect()
        }
    }
}
