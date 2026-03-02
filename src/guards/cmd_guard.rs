//! Command Guard — intercepte les commandes shell dangereuses.
//!
//! Architecture en 2 couches :
//! 1. **CommandMatcher** (logique pure) : commande + règles → verdict
//! 2. **CmdGuard** (Guard trait) : polling processus → détection → mpsc

use crate::config::{AppConfig, CmdGuardConfig};
use crate::types::{Guard, GuardStatus, SecurityEvent, Severity};
use chrono::{Duration, Utc};
use regex::Regex;
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

// ---------------------------------------------------------------------------
// CommandVerdict — résultat du matching d'une commande
// ---------------------------------------------------------------------------

/// Type de match trouvé.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MatchType {
    /// La commande est dans la blacklist (interdite).
    Blacklisted,
    /// La commande nécessite approbation.
    RequiresApproval,
}

/// Verdict rendu par le CommandMatcher pour une commande donnée.
#[derive(Debug, Clone)]
pub struct CommandVerdict {
    pub match_type: MatchType,
    pub severity: Severity,
    pub description: String,
    pub pattern: String,
}

// ---------------------------------------------------------------------------
// CompiledPattern — pattern regex pré-compilé
// ---------------------------------------------------------------------------

struct CompiledBlacklistPattern {
    regex: Regex,
    description: String,
    severity: Severity,
    raw_pattern: String,
}

struct CompiledApprovalPattern {
    regex: Regex,
    description: String,
    raw_pattern: String,
}

// ---------------------------------------------------------------------------
// CommandMatcher — logique pure de matching de commandes
// ---------------------------------------------------------------------------

/// Compare une commande shell contre les listes blacklist et require_approval.
///
/// Priorité : Blacklist > RequireApproval > None.
/// Les regex sont pré-compilées à la construction.
pub struct CommandMatcher {
    blacklist: Vec<CompiledBlacklistPattern>,
    require_approval: Vec<CompiledApprovalPattern>,
}

impl CommandMatcher {
    /// Crée un nouveau matcher à partir de la configuration.
    /// Les regex invalides sont silencieusement ignorées.
    pub fn new(config: &CmdGuardConfig) -> Self {
        let blacklist = config
            .blacklist
            .iter()
            .filter_map(|p| {
                Regex::new(&p.pattern)
                    .ok()
                    .map(|regex| CompiledBlacklistPattern {
                        regex,
                        description: p.description.clone(),
                        severity: Self::parse_severity(&p.severity),
                        raw_pattern: p.pattern.clone(),
                    })
            })
            .collect();

        let require_approval = config
            .require_approval
            .iter()
            .filter_map(|p| {
                Regex::new(&p.pattern)
                    .ok()
                    .map(|regex| CompiledApprovalPattern {
                        regex,
                        description: p.description.clone(),
                        raw_pattern: p.pattern.clone(),
                    })
            })
            .collect();

        Self {
            blacklist,
            require_approval,
        }
    }

    /// Vérifie une commande contre toutes les règles.
    /// Retourne None si aucun match, Some(verdict) sinon.
    /// Priorité : Blacklist > RequireApproval.
    ///
    /// En mode Paranoid, une commande non-matchée est traitée comme blacklistée (default:deny).
    pub fn match_command(
        &self,
        command: &str,
        mode: &crate::types::OperationMode,
    ) -> Option<CommandVerdict> {
        // Commande vide ou whitespace-only → pas de match
        if command.trim().is_empty() {
            return None;
        }

        // Vérifier la blacklist en premier
        for pattern in &self.blacklist {
            if pattern.regex.is_match(command) {
                return Some(CommandVerdict {
                    match_type: MatchType::Blacklisted,
                    severity: pattern.severity.clone(),
                    description: pattern.description.clone(),
                    pattern: pattern.raw_pattern.clone(),
                });
            }
        }

        // Ensuite require_approval
        for pattern in &self.require_approval {
            if pattern.regex.is_match(command) {
                return Some(CommandVerdict {
                    match_type: MatchType::RequiresApproval,
                    severity: Severity::Info,
                    description: pattern.description.clone(),
                    pattern: pattern.raw_pattern.clone(),
                });
            }
        }

        // Shell evasion detection — block encoding/obfuscation in Enforce/Paranoid modes
        if let Some(evasion_desc) = self.check_evasion(command) {
            match mode {
                crate::types::OperationMode::Enforce | crate::types::OperationMode::Paranoid => {
                    return Some(CommandVerdict {
                        match_type: MatchType::Blacklisted,
                        severity: Severity::High,
                        description: format!("Shell evasion detected: {}", evasion_desc),
                        pattern: "shell_evasion".to_string(),
                    });
                }
                crate::types::OperationMode::Monitor => { /* log only, don't block */ }
            }
        }

        // Default:deny en mode Paranoid — toute commande non-matchée est bloquée
        if *mode == crate::types::OperationMode::Paranoid {
            return Some(CommandVerdict {
                match_type: MatchType::Blacklisted,
                severity: Severity::Warning,
                description: "Command not explicitly allowed (paranoid mode)".to_string(),
                pattern: String::new(),
            });
        }

        None
    }

    /// Check if a command uses shell encoding/obfuscation evasion techniques.
    /// In Paranoid mode, these patterns trigger blocking.
    ///
    /// Returns Some(description) if evasion detected, None otherwise.
    pub fn check_evasion(&self, cmd: &str) -> Option<&'static str> {
        /// Meta-patterns for detecting shell obfuscation/encoding evasion.
        const SHELL_EVASION_PATTERNS: &[(&str, &str)] = &[
            (r"\$\(", "command substitution via $()"),
            (r"`[^`]+`", "command substitution via backticks"),
            (r"\\x[0-9a-fA-F]{2}", "hex-encoded characters"),
            (r"\bprintf\b.*\\x", "printf with hex encoding"),
            (r"\beval\b", "eval command execution"),
            (
                r"\bbase64\b.*(decode|--decode|\s-d\b)",
                "base64 decode execution",
            ),
        ];

        for (pattern, description) in SHELL_EVASION_PATTERNS {
            if let Ok(re) = Regex::new(pattern) {
                if re.is_match(cmd) {
                    return Some(description);
                }
            }
        }
        None
    }

    /// Parse une chaîne de severity en enum.
    fn parse_severity(s: &str) -> Severity {
        match s.to_lowercase().as_str() {
            "critical" => Severity::Critical,
            "high" => Severity::High,
            "warning" => Severity::Warning,
            _ => Severity::Info,
        }
    }
}

// ---------------------------------------------------------------------------
// CmdGuard — implémentation du Guard trait
// ---------------------------------------------------------------------------

/// Command Guard : surveille les commandes shell et alerte sur les patterns dangereux.
pub struct CmdGuard {
    config: CmdGuardConfig,
    running: Arc<AtomicBool>,
    events_total: Arc<AtomicU64>,
    events_blocked: Arc<AtomicU64>,
    start_time: Arc<std::sync::Mutex<Option<chrono::DateTime<Utc>>>>,
    cancel_token: CancellationToken,
    task_handle: Arc<tokio::sync::Mutex<Option<tokio::task::JoinHandle<()>>>>,
    /// Shared config for hot-reload and mode access (used in start() I/O layer).
    #[allow(dead_code)]
    app_config: Arc<RwLock<AppConfig>>,
}

impl CmdGuard {
    /// Crée un nouveau CmdGuard à partir de la configuration.
    pub fn new(config: &CmdGuardConfig, app_config: Arc<RwLock<AppConfig>>) -> Self {
        Self {
            config: config.clone(),
            running: Arc::new(AtomicBool::new(false)),
            events_total: Arc::new(AtomicU64::new(0)),
            events_blocked: Arc::new(AtomicU64::new(0)),
            start_time: Arc::new(std::sync::Mutex::new(None)),
            cancel_token: CancellationToken::new(),
            task_handle: Arc::new(tokio::sync::Mutex::new(None)),
            app_config,
        }
    }
}

#[async_trait::async_trait]
impl Guard for CmdGuard {
    fn name(&self) -> &str {
        "cmd_guard"
    }

    async fn start(&self, alert_tx: mpsc::Sender<SecurityEvent>) -> anyhow::Result<()> {
        self.running.store(true, Ordering::SeqCst);
        *self.start_time.lock().expect("lock poisoned") = Some(Utc::now());

        if self.config.enabled {
            let matcher = CommandMatcher::new(&self.config);
            let cancel = self.cancel_token.clone();
            let app_config = Arc::clone(&self.app_config);
            let events_total = Arc::clone(&self.events_total);
            let events_blocked = Arc::clone(&self.events_blocked);
            let poll_interval = std::time::Duration::from_millis(self.config.poll_interval_ms);

            let handle = tokio::spawn(async move {
                let mut scanner = crate::process::ProcessScanner::new();
                let mut seen_pids: HashSet<u32> = HashSet::new();

                loop {
                    tokio::select! {
                        _ = cancel.cancelled() => {
                            tracing::info!("Cmd Guard polling shutting down");
                            break;
                        }
                        _ = tokio::time::sleep(poll_interval) => {
                            scanner.refresh();
                            let all_procs = scanner.scan_all();

                            // Get current mode
                            let mode = app_config
                                .read()
                                .ok()
                                .map(|cfg| match cfg.general.mode.as_str() {
                                    "enforce" => crate::types::OperationMode::Enforce,
                                    "paranoid" => crate::types::OperationMode::Paranoid,
                                    _ => crate::types::OperationMode::Monitor,
                                })
                                .unwrap_or(crate::types::OperationMode::Monitor);

                            // Prune dead PIDs (no longer in process list)
                            let active_pids: HashSet<u32> =
                                all_procs.iter().map(|p| p.pid).collect();
                            seen_pids.retain(|pid| active_pids.contains(pid));

                            for proc in &all_procs {
                                // Skip already-seen PIDs
                                if seen_pids.contains(&proc.pid) {
                                    continue;
                                }

                                // V10: argv[0] mismatch detection
                                if crate::process::check_argv0_mismatch(&proc.name, &proc.cmd) {
                                    tracing::warn!(
                                        "argv[0] mismatch: name='{}' cmd='{}' pid={}",
                                        proc.name,
                                        proc.cmd,
                                        proc.pid
                                    );
                                }

                                // Check command against matcher.
                                // On macOS, sysinfo often returns empty cmd() for processes.
                                // Fall back to checking proc.name if cmd is empty.
                                let check_str = if proc.cmd.trim().is_empty() {
                                    &proc.name
                                } else {
                                    &proc.cmd
                                };
                                if let Some(verdict) = matcher.match_command(check_str, &mode) {
                                    seen_pids.insert(proc.pid);
                                    events_total.fetch_add(1, Ordering::SeqCst);

                                    match verdict.match_type {
                                        MatchType::Blacklisted => {
                                            events_blocked.fetch_add(1, Ordering::SeqCst);
                                            let event = SecurityEvent::new(
                                                crate::types::GuardModule::CmdGuard,
                                                verdict.severity,
                                                crate::types::ActionTaken::Blocked,
                                                format!(
                                                    "Blacklisted command detected (pid {}): {}",
                                                    proc.pid, verdict.description
                                                ),
                                            );
                                            let _ = alert_tx.try_send(event);
                                        }
                                        MatchType::RequiresApproval => {
                                            let event = SecurityEvent::new(
                                                crate::types::GuardModule::CmdGuard,
                                                Severity::Warning,
                                                crate::types::ActionTaken::Alerted,
                                                format!(
                                                    "Command requires approval (pid {}): {}",
                                                    proc.pid, verdict.description
                                                ),
                                            );
                                            let _ = alert_tx.try_send(event);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            });

            *self.task_handle.lock().await = Some(handle);
        }

        Ok(())
    }

    async fn stop(&self) -> anyhow::Result<()> {
        self.running.store(false, Ordering::SeqCst);
        self.cancel_token.cancel();
        if let Some(handle) = self.task_handle.lock().await.take() {
            let _ = handle.await;
        }
        Ok(())
    }

    fn status(&self) -> GuardStatus {
        let running = self.running.load(Ordering::SeqCst);
        let start = self.start_time.lock().expect("lock poisoned");
        let uptime = if let Some(started) = *start {
            if running {
                Utc::now() - started
            } else {
                Duration::zero()
            }
        } else {
            Duration::zero()
        };

        GuardStatus {
            running,
            events_total: self.events_total.load(Ordering::SeqCst),
            events_blocked: self.events_blocked.load(Ordering::SeqCst),
            last_event: None,
            uptime,
        }
    }
}
