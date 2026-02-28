//! Command Guard — intercepte les commandes shell dangereuses.
//!
//! Architecture en 2 couches :
//! 1. **CommandMatcher** (logique pure) : commande + règles → verdict
//! 2. **CmdGuard** (Guard trait) : polling processus → détection → mpsc

use crate::config::CmdGuardConfig;
use crate::types::{Guard, GuardStatus, SecurityEvent, Severity};
use chrono::{Duration, Utc};
use regex::Regex;
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;

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
}

impl CmdGuard {
    /// Crée un nouveau CmdGuard à partir de la configuration.
    pub fn new(config: &CmdGuardConfig) -> Self {
        Self {
            config: config.clone(),
            running: Arc::new(AtomicBool::new(false)),
            events_total: Arc::new(AtomicU64::new(0)),
            events_blocked: Arc::new(AtomicU64::new(0)),
            start_time: Arc::new(std::sync::Mutex::new(None)),
        }
    }
}

#[async_trait::async_trait]
impl Guard for CmdGuard {
    fn name(&self) -> &str {
        "cmd_guard"
    }

    async fn start(&self, _alert_tx: mpsc::Sender<SecurityEvent>) -> anyhow::Result<()> {
        self.running.store(true, Ordering::SeqCst);
        *self.start_time.lock().expect("lock poisoned") = Some(Utc::now());

        if self.config.enabled {
            let _matcher = CommandMatcher::new(&self.config);
            let _seen_pids: HashSet<u32> = HashSet::new();
            // Le polling serait lancé dans un tokio::task ici
        }

        Ok(())
    }

    async fn stop(&self) -> anyhow::Result<()> {
        self.running.store(false, Ordering::SeqCst);
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
