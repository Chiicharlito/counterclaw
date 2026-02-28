//! Daemon orchestrator — charge config, spawne guards + engine + dashboard.
//!
//! Le daemon est le point d'entrée principal quand CounterClaw tourne
//! en mode foreground ou background. Il coordonne tous les modules.

use crate::alerting::engine::AlertingEngine;
use crate::config::AppConfig;
use crate::guards::cdp_proxy::CdpProxy;
use crate::guards::cmd_guard::CmdGuard;
use crate::guards::fs_guard::FsGuard;
use crate::guards::net_guard::NetGuard;
use crate::types::{
    ActionTaken, EventBuffer, Guard, GuardModule, GuardStatus, OperationMode, SecurityEvent,
    Severity,
};
use chrono::{DateTime, Utc};
use std::path::Path;
use std::sync::{Arc, RwLock};
use tokio::sync::mpsc;

// ---------------------------------------------------------------------------
// PID file management
// ---------------------------------------------------------------------------

/// Écrit le PID dans un fichier.
pub fn write_pid_file(path: &Path, pid: u32) -> Result<(), std::io::Error> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, pid.to_string())
}

/// Lit le PID depuis un fichier.
pub fn read_pid_file(path: &Path) -> Option<u32> {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| s.trim().parse().ok())
}

/// Supprime le fichier PID.
pub fn remove_pid_file(path: &Path) {
    let _ = std::fs::remove_file(path);
}

// ---------------------------------------------------------------------------
// DaemonState — état partagé du daemon
// ---------------------------------------------------------------------------

/// État du daemon, partagé avec le dashboard.
pub struct DaemonState {
    pub config: AppConfig,
    pub start_time: DateTime<Utc>,
    pub event_buffer: Arc<RwLock<EventBuffer>>,
    guards: Vec<Arc<dyn Guard>>,
}

impl DaemonState {
    /// Crée un nouvel état de daemon avec les guards instanciés (pas encore démarrés).
    pub fn new(config: AppConfig, event_buffer: Arc<RwLock<EventBuffer>>) -> Self {
        let guards: Vec<Arc<dyn Guard>> = vec![
            Arc::new(FsGuard::new(&config.fs_guard)),
            Arc::new(CdpProxy::new(&config.cdp_proxy)),
            Arc::new(NetGuard::new(&config.net_guard)),
            Arc::new(CmdGuard::new(&config.cmd_guard)),
        ];

        Self {
            config,
            start_time: Utc::now(),
            event_buffer,
            guards,
        }
    }

    /// Retourne le mode d'opération.
    pub fn mode(&self) -> OperationMode {
        self.config.operation_mode()
    }

    /// Retourne les statuts de tous les guards.
    pub fn guard_statuses(&self) -> Vec<(String, GuardStatus)> {
        self.guards
            .iter()
            .map(|g| (g.name().to_string(), g.status()))
            .collect()
    }

    /// Démarre tous les guards activés.
    pub async fn start_guards(&self, alert_tx: mpsc::Sender<SecurityEvent>) {
        for guard in &self.guards {
            if let Err(e) = guard.start(alert_tx.clone()).await {
                tracing::error!("Failed to start guard {}: {}", guard.name(), e);
            }
        }
    }

    /// Arrête tous les guards proprement.
    pub async fn stop_guards(&self) {
        for guard in &self.guards {
            if let Err(e) = guard.stop().await {
                tracing::error!("Failed to stop guard {}: {}", guard.name(), e);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Daemon — orchestrateur principal
// ---------------------------------------------------------------------------

/// Le daemon principal — orchestre guards, engine, et signals.
pub struct Daemon {
    config: AppConfig,
    event_buffer: Arc<RwLock<EventBuffer>>,
}

impl Daemon {
    /// Crée un nouveau daemon.
    pub fn new(config: AppConfig, event_buffer: Arc<RwLock<EventBuffer>>) -> Self {
        Self {
            config,
            event_buffer,
        }
    }

    /// Boucle principale — démarre tout et attend un signal d'arrêt.
    pub async fn run_until_signal(self) {
        let mode = self.config.operation_mode();

        // Canal mpsc pour les événements
        let (alert_tx, alert_rx) = mpsc::channel::<SecurityEvent>(1000);

        // Créer le state partagé
        let state = DaemonState::new(self.config.clone(), self.event_buffer.clone());

        // Lancer le moteur d'alerting
        let engine = AlertingEngine::new(&self.config.alerting, self.event_buffer.clone());
        let engine_handle = tokio::spawn(async move {
            engine.run(alert_rx).await;
        });

        // Démarrer les guards
        state.start_guards(alert_tx.clone()).await;

        // Événement de démarrage
        let startup = SecurityEvent::new(
            GuardModule::System,
            Severity::Info,
            ActionTaken::Logged,
            format!("CounterClaw started in {} mode", mode),
        );
        let _ = alert_tx.send(startup).await;

        // Attendre Ctrl+C
        match tokio::signal::ctrl_c().await {
            Ok(()) => {
                tracing::info!("Received shutdown signal");
            }
            Err(e) => {
                tracing::error!("Failed to listen for Ctrl+C: {}", e);
            }
        }

        // Graceful shutdown
        state.stop_guards().await;
        drop(alert_tx);
        let _ = engine_handle.await;
    }
}
