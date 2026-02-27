//! Moteur d'alerting central — le dispatcher.
//!
//! L'engine tourne dans sa propre tâche tokio. Il reçoit les SecurityEvent
//! de tous les modules via un canal mpsc, et les dispatche vers les
//! différents backends : logger, notification macOS, (et plus tard Slack).
//!
//! Le kill switch vit aussi ici : il compte les violations récentes
//! et déclenche une action si le seuil est dépassé.

use crate::alerting::logger::EventLogger;
use crate::alerting::macos_notify::MacosNotifier;
use crate::config::AlertingConfig;
use crate::types::{ActionTaken, GuardModule, SecurityEvent, Severity};
use chrono::{DateTime, Utc};
use std::collections::VecDeque;
use tokio::sync::mpsc;

/// Le moteur d'alerting central.
pub struct AlertingEngine {
    logger: EventLogger,
    notifier: MacosNotifier,
    kill_switch: KillSwitch,
}

impl AlertingEngine {
    /// Crée le moteur d'alerting à partir de la configuration.
    pub fn new(config: &AlertingConfig) -> Self {
        let logger = EventLogger::new(
            &config.file_log.path,
            config.file_log.max_size_mb,
            config.file_log.keep_files,
        );

        let notifier = MacosNotifier::new(config.macos_notification.enabled);

        let kill_switch = KillSwitch::new(&config.kill_switch);

        Self {
            logger,
            notifier,
            kill_switch,
        }
    }

    /// Lance la boucle de dispatch. Cette méthode bloque jusqu'à ce que
    /// le canal soit fermé (tous les senders sont droppés).
    pub async fn run(mut self, mut rx: mpsc::Receiver<SecurityEvent>) {
        while let Some(event) = rx.recv().await {
            // 1. Toujours logger dans le fichier
            self.logger.log(&event);

            // 2. Notification macOS si le niveau est suffisant
            if self.notifier.is_enabled() && event.severity >= Severity::Warning {
                self.notifier.send(&event);
            }

            // 3. Kill switch : enregistrer et vérifier
            self.kill_switch.record_event(&event);
            if self.kill_switch.should_trigger() {
                self.kill_switch.execute(&self.logger, &self.notifier);
            }
        }

        // Le canal est fermé → shutdown propre
        tracing::info!("Alerting engine shutting down");
    }
}

// ---------------------------------------------------------------------------
// Kill Switch — arrêt d'urgence
// ---------------------------------------------------------------------------

/// Le kill switch surveille le rythme des violations.
/// Si N violations de gravité >= seuil arrivent en M secondes,
/// il déclenche une action d'urgence (log + notification pour le MVP).
struct KillSwitch {
    enabled: bool,
    threshold_severity: Severity,
    threshold_count: usize,
    threshold_window_seconds: i64,
    action: String,
    recent_events: VecDeque<DateTime<Utc>>,
    triggered: bool,
}

impl KillSwitch {
    fn new(config: &crate::config::KillSwitchConfig) -> Self {
        let threshold_severity = match config.threshold_severity.as_str() {
            "info" => Severity::Info,
            "warning" => Severity::Warning,
            "high" => Severity::High,
            "critical" => Severity::Critical,
            _ => Severity::Warning,
        };

        Self {
            enabled: config.enabled,
            threshold_severity,
            threshold_count: config.threshold_count as usize,
            threshold_window_seconds: config.threshold_window_seconds as i64,
            action: config.action.clone(),
            recent_events: VecDeque::new(),
            triggered: false,
        }
    }

    /// Enregistre un événement dans la fenêtre glissante.
    fn record_event(&mut self, event: &SecurityEvent) {
        if !self.enabled || event.severity < self.threshold_severity {
            return;
        }

        self.recent_events.push_back(event.timestamp);

        // Nettoyer les événements hors de la fenêtre
        let cutoff = Utc::now() - chrono::Duration::seconds(self.threshold_window_seconds);
        while self.recent_events.front().is_some_and(|t| *t < cutoff) {
            self.recent_events.pop_front();
        }
    }

    /// Vérifie si le seuil est atteint.
    fn should_trigger(&self) -> bool {
        self.enabled && !self.triggered && self.recent_events.len() >= self.threshold_count
    }

    /// Exécute l'action du kill switch.
    /// En MVP : log + notification. Le vrai kill de process viendra en Phase 2.
    fn execute(&mut self, logger: &EventLogger, notifier: &MacosNotifier) {
        self.triggered = true;

        let description = format!(
            "Kill switch triggered: {} violations in {}s window (action: {})",
            self.recent_events.len(),
            self.threshold_window_seconds,
            self.action
        );

        tracing::error!("{}", description);

        let event = SecurityEvent::new(
            GuardModule::System,
            Severity::Critical,
            ActionTaken::Blocked,
            description,
        );

        logger.log(&event);
        notifier.send(&event);
    }
}
