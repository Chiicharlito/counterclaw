//! Moteur d'alerting central — le dispatcher.
//!
//! L'engine tourne dans sa propre tâche tokio. Il reçoit les SecurityEvent
//! de tous les modules via un canal mpsc, et les dispatche vers les
//! différents backends : logger, notification macOS, Slack.
//!
//! Le kill switch vit aussi ici : il compte les violations récentes
//! et déclenche une action si le seuil est dépassé.

use crate::alerting::logger::EventLogger;
use crate::alerting::macos_notify::MacosNotifier;
use crate::alerting::slack::SlackNotifier;
use crate::config::AlertingConfig;
use crate::types::{ActionTaken, EventBuffer, GuardModule, SecurityEvent, Severity};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, RwLock};
use std::time::Instant;
use tokio::sync::mpsc;

/// Checks if a kill switch action string should trigger process killing.
///
/// Returns true for "kill" and "suspend_openclaw" actions.
/// Returns false for "alert_only" or any unknown action.
pub fn kill_switch_should_kill(action: &str) -> bool {
    matches!(action, "kill" | "suspend_openclaw")
}

/// Checks if a SecurityEvent should be excluded from kill switch event counting.
///
/// Only FsGuard events can be excluded (system noise filtering).
/// Returns true if the event's description contains any of the exclude patterns.
pub fn should_exclude_from_kill_switch(event: &SecurityEvent, exclude_patterns: &[String]) -> bool {
    // Only exclude FsGuard events (system noise is filesystem-specific)
    if event.module != GuardModule::FsGuard {
        return false;
    }

    // Check if description matches any exclude pattern
    for pattern in exclude_patterns {
        if event.description.contains(pattern.as_str()) {
            return true;
        }
    }

    false
}

/// Per-module rate limiter for the alerting engine.
/// Implements a sliding window of max_per_second events per module.
struct ModuleRateLimiter {
    /// module_name -> (window_start, count)
    windows: HashMap<String, (Instant, u32)>,
    max_per_second: u32,
}

impl ModuleRateLimiter {
    fn new(max_per_second: u32) -> Self {
        Self {
            windows: HashMap::new(),
            max_per_second,
        }
    }

    /// Returns true if the event should be processed, false if rate-limited.
    fn check(&mut self, module: &str) -> bool {
        let now = Instant::now();
        let entry = self.windows.entry(module.to_string()).or_insert((now, 0));

        // If more than 1 second has passed, reset the window
        if now.duration_since(entry.0).as_secs() >= 1 {
            *entry = (now, 1);
            return true;
        }

        // Within the same second window
        if entry.1 < self.max_per_second {
            entry.1 += 1;
            true
        } else {
            false
        }
    }
}

/// Le moteur d'alerting central.
pub struct AlertingEngine {
    logger: EventLogger,
    notifier: MacosNotifier,
    slack: SlackNotifier,
    kill_switch: KillSwitch,
    event_buffer: Arc<RwLock<EventBuffer>>,
    rate_limiter: ModuleRateLimiter,
}

impl AlertingEngine {
    /// Crée le moteur d'alerting à partir de la configuration et d'un buffer partagé.
    pub fn new(config: &AlertingConfig, event_buffer: Arc<RwLock<EventBuffer>>) -> Self {
        let logger = EventLogger::new(
            &config.file_log.path,
            config.file_log.max_size_mb,
            config.file_log.keep_files,
        );

        let notifier = MacosNotifier::new(config.macos_notification.enabled);

        let slack = SlackNotifier::new(&config.slack);

        let kill_switch = KillSwitch::new(&config.kill_switch);

        Self {
            logger,
            notifier,
            slack,
            kill_switch,
            event_buffer,
            rate_limiter: ModuleRateLimiter::new(100),
        }
    }

    /// Lance la boucle de dispatch. Cette méthode bloque jusqu'à ce que
    /// le canal soit fermé (tous les senders sont droppés).
    pub async fn run(mut self, mut rx: mpsc::Receiver<SecurityEvent>) {
        while let Some(event) = rx.recv().await {
            // 0. Rate limiting per module (max 100 events/second/module)
            let module_name = event.module.to_string();
            if !self.rate_limiter.check(&module_name) {
                // Rate-limited — still log but skip notifications
                self.logger.log(&event);
                continue;
            }

            // 1. Toujours logger dans le fichier
            self.logger.log(&event);

            // 2. Notification macOS si le niveau est suffisant
            if self.notifier.is_enabled() && event.severity >= Severity::Warning {
                self.notifier.send(&event);
            }

            // 3. Slack notification (async, best-effort)
            if self.slack.should_notify(&event) {
                let slack = self.slack.clone();
                let event_clone = event.clone();
                tokio::spawn(async move {
                    if let Err(e) = slack.send(&event_clone).await {
                        tracing::warn!("Slack notification failed: {}", e);
                    }
                });
            }

            // 4. Push event dans le buffer partagé
            if let Ok(mut buf) = self.event_buffer.write() {
                buf.push(event.clone());
            }

            // 5. Kill switch : enregistrer, check reset, et vérifier
            self.kill_switch.check_reset();
            self.kill_switch.record_event(&event);
            if self.kill_switch.should_trigger() {
                let kill_event = self.kill_switch.execute(&self.logger, &self.notifier);
                // Push kill switch event to buffer for visibility
                if let Ok(mut buf) = self.event_buffer.write() {
                    buf.push(kill_event);
                }
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
///
/// V9: Uses std::time::Instant (monotonic clock) for window tracking instead of
/// Utc::now() which can be manipulated by setting the system clock back.
struct KillSwitch {
    enabled: bool,
    threshold_severity: Severity,
    threshold_count: usize,
    threshold_window_seconds: u64,
    action: String,
    /// Process patterns to kill when triggered.
    watch_processes: Vec<String>,
    /// Path patterns to exclude from event counting (e.g., Keychain noise).
    exclude_path_patterns: Vec<String>,
    /// V9: Monotonic timestamps for violation window tracking.
    /// Using Instant instead of DateTime<Utc> to prevent clock manipulation attacks.
    recent_violations: VecDeque<Instant>,
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
            threshold_window_seconds: config.threshold_window_seconds,
            action: config.action.clone(),
            watch_processes: config.watch_processes.clone(),
            exclude_path_patterns: config.exclude_path_patterns.clone(),
            recent_violations: VecDeque::new(),
            triggered: false,
        }
    }

    /// Enregistre un événement dans la fenêtre glissante.
    /// V9: Uses Instant (monotonic clock) instead of Utc::now() to prevent
    /// clock manipulation attacks where an attacker sets the system time back.
    /// BUG 5: Events matching exclude_path_patterns are not counted (noise filtering).
    fn record_event(&mut self, event: &SecurityEvent) {
        if !self.enabled || event.severity < self.threshold_severity {
            return;
        }

        // BUG 5: Skip events matching exclude patterns (e.g., Keychain noise)
        if should_exclude_from_kill_switch(event, &self.exclude_path_patterns) {
            return;
        }

        let now = Instant::now();
        self.recent_violations.push_back(now);

        // Nettoyer les violations hors de la fenêtre (monotonic)
        let window = std::time::Duration::from_secs(self.threshold_window_seconds);
        while let Some(front) = self.recent_violations.front() {
            if now.duration_since(*front) > window {
                self.recent_violations.pop_front();
            } else {
                break;
            }
        }
    }

    /// Reset the kill switch if the time window has passed with no recent violations.
    /// V9: Uses Instant for monotonic timing.
    fn check_reset(&mut self) {
        if !self.triggered {
            return;
        }
        let now = Instant::now();
        let window = std::time::Duration::from_secs(self.threshold_window_seconds);

        // If all recent violations are outside the window, reset
        let has_recent = self
            .recent_violations
            .iter()
            .any(|t| now.duration_since(*t) <= window);
        if !has_recent {
            self.triggered = false;
            self.recent_violations.clear();
            tracing::info!("Kill switch reset — no recent violations in window");
        }
    }

    /// Vérifie si le seuil est atteint.
    fn should_trigger(&self) -> bool {
        self.enabled && !self.triggered && self.recent_violations.len() >= self.threshold_count
    }

    /// Exécute l'action du kill switch.
    ///
    /// Si `action` est "kill" ou "suspend_openclaw" et `watch_processes` est non-vide,
    /// tente de tuer les processus correspondants via ProcessScanner + kill_process().
    /// Sinon, log + notification seulement.
    ///
    /// Returns the kill switch SecurityEvent for buffer storage.
    fn execute(&mut self, logger: &EventLogger, notifier: &MacosNotifier) -> SecurityEvent {
        self.triggered = true;

        let mut description = format!(
            "Kill switch triggered: {} violations in {}s window (action: {})",
            self.recent_violations.len(),
            self.threshold_window_seconds,
            self.action
        );

        // Attempt actual process killing if configured
        if kill_switch_should_kill(&self.action) && !self.watch_processes.is_empty() {
            let scanner = crate::process::ProcessScanner::new();
            let targets = scanner.find_matching(&self.watch_processes);

            if targets.is_empty() {
                tracing::warn!(
                    "Kill switch: no matching processes found for patterns: {:?}",
                    self.watch_processes
                );
                description.push_str(" — no matching processes found");
            } else {
                let mut killed_pids = Vec::new();
                for target in &targets {
                    match crate::process::kill_process(target.pid) {
                        Ok(true) => {
                            tracing::error!(
                                "Kill switch: killed process {} (pid {})",
                                target.name,
                                target.pid
                            );
                            killed_pids.push(target.pid);
                        }
                        Ok(false) => {
                            tracing::warn!(
                                "Kill switch: process {} (pid {}) not found",
                                target.name,
                                target.pid
                            );
                        }
                        Err(e) => {
                            tracing::error!(
                                "Kill switch: failed to kill process {} (pid {}): {}",
                                target.name,
                                target.pid,
                                e
                            );
                        }
                    }
                }
                if !killed_pids.is_empty() {
                    description.push_str(&format!(" — killed PIDs: {:?}", killed_pids));
                }
            }
        }

        tracing::error!("{}", description);

        let event = SecurityEvent::new(
            GuardModule::System,
            Severity::Critical,
            ActionTaken::Blocked,
            description,
        );

        logger.log(&event);
        notifier.send(&event);
        event
    }
}
