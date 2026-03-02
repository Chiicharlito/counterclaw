//! Command Guard — intercepte les commandes shell dangereuses.
//!
//! Architecture en 2 couches :
//! 1. **CommandMatcher** (logique pure) : commande + règles → verdict
//! 2. **CmdGuard** (Guard trait) : détection processus → verdict → mpsc
//!
//! Sur macOS, utilise KqueueMonitor pour la détection en temps réel (kqueue EVFILT_PROC).
//! Sur Linux, utilise le polling ProcessScanner avec AdaptivePoller.

use crate::config::{AppConfig, CmdGuardConfig};
#[cfg(not(target_os = "macos"))]
use crate::guards::adaptive_poller::AdaptivePoller;
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
// Shared helpers for command verdict processing
// ---------------------------------------------------------------------------

/// Read current operation mode from shared config.
fn read_mode(app_config: &RwLock<AppConfig>) -> crate::types::OperationMode {
    app_config
        .read()
        .ok()
        .map(|cfg| match cfg.general.mode.as_str() {
            "enforce" => crate::types::OperationMode::Enforce,
            "paranoid" => crate::types::OperationMode::Paranoid,
            _ => crate::types::OperationMode::Monitor,
        })
        .unwrap_or(crate::types::OperationMode::Monitor)
}

/// Shared context for command verdict processing (avoids too many function parameters).
struct VerdictContext<'a> {
    matcher: &'a CommandMatcher,
    events_total: &'a AtomicU64,
    events_blocked: &'a AtomicU64,
    alert_tx: &'a mpsc::Sender<SecurityEvent>,
}

/// Process a detected command through CommandMatcher and emit SecurityEvent if matched.
fn process_command_verdict(
    pid: u32,
    name: &str,
    cmd_str: &str,
    mode: &crate::types::OperationMode,
    seen_pids: &mut HashSet<u32>,
    ctx: &VerdictContext<'_>,
) {
    if seen_pids.contains(&pid) {
        return;
    }

    // V10: argv[0] mismatch detection
    if crate::process::check_argv0_mismatch(name, cmd_str) {
        tracing::warn!(
            "argv[0] mismatch: name='{}' cmd='{}' pid={}",
            name,
            cmd_str,
            pid
        );
    }

    let check_str = if cmd_str.trim().is_empty() {
        name
    } else {
        cmd_str
    };

    if let Some(verdict) = ctx.matcher.match_command(check_str, mode) {
        seen_pids.insert(pid);
        ctx.events_total.fetch_add(1, Ordering::SeqCst);

        match verdict.match_type {
            MatchType::Blacklisted => {
                ctx.events_blocked.fetch_add(1, Ordering::SeqCst);
                let event = SecurityEvent::new(
                    crate::types::GuardModule::CmdGuard,
                    verdict.severity,
                    crate::types::ActionTaken::Blocked,
                    format!(
                        "Blacklisted command detected (pid {}): {}",
                        pid, verdict.description
                    ),
                );
                let _ = ctx.alert_tx.try_send(event);
            }
            MatchType::RequiresApproval => {
                let event = SecurityEvent::new(
                    crate::types::GuardModule::CmdGuard,
                    Severity::Warning,
                    crate::types::ActionTaken::Alerted,
                    format!(
                        "Command requires approval (pid {}): {}",
                        pid, verdict.description
                    ),
                );
                let _ = ctx.alert_tx.try_send(event);
            }
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

            // macOS: KqueueMonitor for real-time process detection via kqueue EVFILT_PROC.
            // Detects processes matching blacklist/approval patterns (including ephemeral <50ms).
            #[cfg(target_os = "macos")]
            let handle = {
                use crate::guards::kqueue_monitor::KqueueMonitor;
                use crate::guards::process_monitor::{DetectedProcess, ProcessMonitor};

                // Build watch patterns from blacklist + approval rules
                let mut watch_patterns: Vec<String> = self
                    .config
                    .blacklist
                    .iter()
                    .map(|p| p.pattern.clone())
                    .collect();
                watch_patterns.extend(
                    self.config
                        .require_approval
                        .iter()
                        .map(|p| p.pattern.clone()),
                );
                // In Paranoid mode, catch ALL commands (default:deny)
                if read_mode(&self.app_config) == crate::types::OperationMode::Paranoid {
                    watch_patterns.push(".*".to_string());
                }

                let monitor = KqueueMonitor::new(watch_patterns);
                let (proc_tx, mut proc_rx) = tokio::sync::mpsc::channel::<DetectedProcess>(256);
                let cancel_monitor = cancel.clone();

                tokio::spawn(async move {
                    // Start kqueue monitor in a subtask (handles NEW processes only)
                    let _monitor_task = tokio::spawn(async move {
                        let _ = monitor.start(proc_tx, cancel_monitor).await;
                    });

                    let mut seen_pids: HashSet<u32> = HashSet::new();
                    let ctx = VerdictContext {
                        matcher: &matcher,
                        events_total: &events_total,
                        events_blocked: &events_blocked,
                        alert_tx: &alert_tx,
                    };

                    // Initial scan: detect EXISTING processes (one-time).
                    // KqueueMonitor only catches new fork/exec events, so we need
                    // this scan to find already-running processes at startup.
                    {
                        let mut scanner = crate::process::ProcessScanner::new();
                        scanner.refresh();
                        let all_procs = scanner.scan_all();
                        let mode = read_mode(&app_config);
                        for proc in &all_procs {
                            process_command_verdict(
                                proc.pid,
                                &proc.name,
                                &proc.cmd,
                                &mode,
                                &mut seen_pids,
                                &ctx,
                            );
                        }
                    }

                    // Then listen for kqueue detections (new processes)
                    loop {
                        tokio::select! {
                            _ = cancel.cancelled() => {
                                tracing::info!("Cmd Guard kqueue shutting down");
                                break;
                            }
                            result = proc_rx.recv() => {
                                match result {
                                    Some(detected) => {
                                        let cmd_str = detected.cmd.join(" ");
                                        let mode = read_mode(&app_config);
                                        process_command_verdict(
                                            detected.pid,
                                            &detected.name,
                                            &cmd_str,
                                            &mode,
                                            &mut seen_pids,
                                            &ctx,
                                        );
                                    }
                                    None => break,
                                }
                            }
                        }
                    }
                })
            };

            // Linux/fallback: polling with ProcessScanner + AdaptivePoller.
            // Scans all processes at configurable interval (default 500ms).
            #[cfg(not(target_os = "macos"))]
            let handle = {
                let watch_processes = self.config.watch_processes.clone();
                let active_interval =
                    std::time::Duration::from_millis(self.config.poll_interval_ms);
                let idle_interval =
                    std::time::Duration::from_millis(self.config.idle_poll_interval_ms);

                tokio::spawn(async move {
                    let mut scanner = crate::process::ProcessScanner::new();
                    let mut seen_pids: HashSet<u32> = HashSet::new();
                    let ctx = VerdictContext {
                        matcher: &matcher,
                        events_total: &events_total,
                        events_blocked: &events_blocked,
                        alert_tx: &alert_tx,
                    };
                    let mut poller = AdaptivePoller::with_intervals(
                        idle_interval,
                        active_interval,
                        std::time::Duration::from_secs(5),
                        3,
                    );

                    loop {
                        tokio::select! {
                            _ = cancel.cancelled() => {
                                tracing::info!("Cmd Guard polling shutting down");
                                break;
                            }
                            _ = tokio::time::sleep(if watch_processes.is_empty() {
                                active_interval
                            } else {
                                poller.current_interval()
                            }) => {
                                // Adaptive polling: check if watched processes are active
                                if !watch_processes.is_empty() {
                                    let watched_found =
                                        scanner.has_watched_processes(&watch_processes);
                                    poller.transition(watched_found);
                                    if matches!(
                                        poller.state(),
                                        crate::guards::adaptive_poller::PollerState::Idle
                                    ) {
                                        continue;
                                    }
                                }

                                scanner.refresh();
                                let all_procs = scanner.scan_all();

                                let mode = read_mode(&app_config);

                                // Prune dead PIDs
                                let active_pids: HashSet<u32> =
                                    all_procs.iter().map(|p| p.pid).collect();
                                seen_pids.retain(|pid| active_pids.contains(pid));

                                for proc in &all_procs {
                                    process_command_verdict(
                                        proc.pid,
                                        &proc.name,
                                        &proc.cmd,
                                        &mode,
                                        &mut seen_pids,
                                        &ctx,
                                    );
                                }
                            }
                        }
                    }
                })
            };

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
