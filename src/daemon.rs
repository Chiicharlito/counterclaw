//! Daemon orchestrator — charge config, spawne guards + engine + dashboard.
//!
//! Le daemon est le point d'entrée principal quand CounterClaw tourne
//! en mode foreground ou background. Il coordonne tous les modules.

use crate::alerting::engine::AlertingEngine;
use crate::config::{expand_tilde, AppConfig};
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
///
/// La config est dans un `Arc<RwLock<>>` pour permettre le hot-reload
/// sans redémarrer le daemon.
pub struct DaemonState {
    pub config: Arc<RwLock<AppConfig>>,
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
            config: Arc::new(RwLock::new(config)),
            start_time: Utc::now(),
            event_buffer,
            guards,
        }
    }

    /// Retourne le mode d'opération.
    pub fn mode(&self) -> OperationMode {
        self.config
            .read()
            .expect("config read lock")
            .operation_mode()
    }

    /// Tente de recharger la config depuis un fichier.
    ///
    /// Si le YAML est valide et passe la validation, la config est mise à jour.
    /// Sinon, l'ancienne config est préservée (fail-safe).
    pub fn reload_config(&self, path: &std::path::Path) -> Result<(), String> {
        let new_config = AppConfig::load(path).map_err(|e| format!("{}", e))?;
        let errors = new_config.validate();
        if !errors.is_empty() {
            return Err(format!("Validation failed: {}", errors.join(", ")));
        }
        let mut cfg = self.config.write().expect("config write lock");
        *cfg = new_config;
        Ok(())
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
    ///
    /// Les valeurs de config qui ne supportent pas le hot-reload (ports,
    /// PID path, bind address) sont copiées au démarrage.
    pub async fn run_until_signal(self) {
        let mode = self.config.operation_mode();
        let pid_path = expand_tilde(&self.config.general.pid_file);
        let dashboard_enabled = self.config.dashboard.enabled;
        let dashboard_addr = format!(
            "{}:{}",
            self.config.dashboard.bind_address, self.config.dashboard.port
        );

        // Écrire le PID file
        if let Err(e) = write_pid_file(&pid_path, std::process::id()) {
            tracing::error!("Failed to write PID file: {}", e);
        }

        // Canal mpsc pour les événements
        let (alert_tx, alert_rx) = mpsc::channel::<SecurityEvent>(1000);

        // Créer le state partagé (Arc pour partage avec le dashboard)
        let state = Arc::new(DaemonState::new(
            self.config.clone(),
            self.event_buffer.clone(),
        ));

        // Lancer le moteur d'alerting
        let engine = AlertingEngine::new(&self.config.alerting, self.event_buffer.clone());
        let engine_handle = tokio::spawn(async move {
            engine.run(alert_rx).await;
        });

        // Démarrer les guards
        state.start_guards(alert_tx.clone()).await;

        // Démarrer le dashboard HTTP si activé
        let dashboard_handle = if dashboard_enabled {
            let router = crate::dashboard::server::build_router(Arc::clone(&state));
            match tokio::net::TcpListener::bind(&dashboard_addr).await {
                Ok(listener) => {
                    tracing::info!("Dashboard listening on {}", dashboard_addr);
                    Some(tokio::spawn(async move {
                        if let Err(e) = axum::serve(listener, router).await {
                            tracing::error!("Dashboard server error: {}", e);
                        }
                    }))
                }
                Err(e) => {
                    tracing::error!("Failed to bind dashboard to {}: {}", dashboard_addr, e);
                    None
                }
            }
        } else {
            None
        };

        // Configurer le hot-reload via notify watcher
        let _watcher = self.setup_config_watcher(Arc::clone(&state), alert_tx.clone());

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
        if let Some(handle) = dashboard_handle {
            handle.abort();
        }
        state.stop_guards().await;
        drop(alert_tx);
        let _ = engine_handle.await;

        // Supprimer le PID file
        remove_pid_file(&pid_path);
    }

    /// Configure un watcher `notify` sur le fichier de config pour hot-reload.
    ///
    /// Retourne le watcher (doit rester vivant pour que la surveillance continue).
    /// Si le watcher ne peut pas être créé, log l'erreur et retourne None.
    fn setup_config_watcher(
        &self,
        state: Arc<DaemonState>,
        alert_tx: mpsc::Sender<SecurityEvent>,
    ) -> Option<notify::RecommendedWatcher> {
        let config_path = expand_tilde(&self.config.general.pid_file)
            .parent()
            .map(|p| p.join("config.yaml"))
            .unwrap_or_else(crate::config::default_config_path);

        let config_path_for_handler = config_path.clone();

        let mut watcher =
            notify::recommended_watcher(move |res: Result<notify::Event, notify::Error>| {
                if let Ok(event) = res {
                    if matches!(
                        event.kind,
                        notify::EventKind::Modify(_) | notify::EventKind::Create(_)
                    ) {
                        match state.reload_config(&config_path_for_handler) {
                            Ok(()) => {
                                tracing::info!("Config reloaded successfully");
                                let reload_event = SecurityEvent::new(
                                    GuardModule::System,
                                    Severity::Info,
                                    ActionTaken::Logged,
                                    "Configuration reloaded".to_string(),
                                );
                                let _ = alert_tx.blocking_send(reload_event);
                            }
                            Err(e) => {
                                tracing::warn!("Config reload failed (keeping old config): {}", e);
                            }
                        }
                    }
                }
            })
            .ok()?;

        use notify::Watcher;
        if let Err(e) = watcher.watch(&config_path, notify::RecursiveMode::NonRecursive) {
            tracing::warn!("Failed to watch config file {:?}: {}", config_path, e);
            return None;
        }

        tracing::info!("Config hot-reload enabled for {:?}", config_path);
        Some(watcher)
    }
}
