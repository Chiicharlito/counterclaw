//! Filesystem Guard — surveille les accès fichier des processus OpenClaw.
//!
//! Architecture en 3 couches :
//! 1. **PathMatcher** (logique pure) : chemin + règles → verdict
//! 2. **FsEventHandler** (orchestration) : reçoit events notify → filtre → mpsc
//! 3. **FsGuard** (Guard trait) : lifecycle start/stop/status

use crate::config::{expand_tilde, FsGuardConfig};
use crate::types::{ActionTaken, Guard, GuardModule, GuardStatus, SecurityEvent, Severity};
use chrono::{Duration, Utc};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;

// ---------------------------------------------------------------------------
// Self-protection paths — always blocked regardless of mode or user config
// ---------------------------------------------------------------------------

/// Paths that CounterClaw uses for its own operation.
/// These are ALWAYS blocked to prevent an agent from tampering with the daemon.
/// Matching is hierarchical: any file under these directories is also blocked.
pub const SELF_PROTECTION_PATHS: &[&str] = &[
    "/etc/counterclaw/",
    "/var/log/counterclaw/",
    "/var/run/counterclaw.pid",
    "/Library/LaunchDaemons/io.counterclaw.daemon.plist",
    "/usr/local/bin/counterclaw",
];

// ---------------------------------------------------------------------------
// PathVerdict — résultat du matching d'un chemin
// ---------------------------------------------------------------------------

/// Verdict rendu par le PathMatcher pour un chemin donné.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathVerdict {
    /// Accès totalement interdit.
    Blocked,
    /// Lecture autorisée, écriture interdite.
    ReadOnly,
    /// Accès pleinement autorisé.
    Allowed,
    /// Chemin non couvert par les règles.
    Unmatched,
}

// ---------------------------------------------------------------------------
// PathMatcher — logique pure de matching de chemins
// ---------------------------------------------------------------------------

/// Compare un chemin contre les listes blocked/read_only/allowed.
///
/// Priorité : SelfProtection > Blocked > ReadOnly > Allowed > Unmatched.
///
/// Gère :
/// - Self-protection paths (always blocked, even in Monitor mode)
/// - Symlink detection and resolution (prevents bypass via symlinks)
/// - Tilde expansion (~/ → /Users/xxx/)
/// - Glob patterns (ex: ~/.env.*)
/// - Canonicalisation (résout ../, //, symlinks)
/// - Matching hiérarchique (sous-répertoire d'un blocked = blocked)
pub struct PathMatcher {
    blocked: Vec<PathBuf>,
    blocked_globs: Vec<glob::Pattern>,
    read_only: Vec<PathBuf>,
    read_only_globs: Vec<glob::Pattern>,
    allowed: Vec<PathBuf>,
    allowed_globs: Vec<glob::Pattern>,
}

impl PathMatcher {
    /// Crée un nouveau matcher à partir de listes de chemins (strings).
    /// Les tildes sont expandus, les globs sont séparés des chemins exacts.
    pub fn new(blocked: Vec<String>, read_only: Vec<String>, allowed: Vec<String>) -> Self {
        let (blocked_paths, blocked_globs) = Self::parse_paths(&blocked);
        let (read_only_paths, read_only_globs) = Self::parse_paths(&read_only);
        let (allowed_paths, allowed_globs) = Self::parse_paths(&allowed);

        Self {
            blocked: blocked_paths,
            blocked_globs,
            read_only: read_only_paths,
            read_only_globs,
            allowed: allowed_paths,
            allowed_globs,
        }
    }

    /// Sépare les chemins en deux groupes : exacts et globs.
    fn parse_paths(paths: &[String]) -> (Vec<PathBuf>, Vec<glob::Pattern>) {
        let mut exact = Vec::new();
        let mut globs = Vec::new();

        for raw in paths {
            let expanded = expand_tilde(raw);
            let expanded_str = expanded.to_string_lossy().to_string();

            // Si le chemin contient des caractères glob, le traiter comme glob
            if expanded_str.contains('*')
                || expanded_str.contains('?')
                || expanded_str.contains('[')
            {
                if let Ok(pattern) = glob::Pattern::new(&expanded_str) {
                    globs.push(pattern);
                }
            } else {
                exact.push(expanded);
            }
        }

        (exact, globs)
    }

    /// Vérifie un chemin contre toutes les règles.
    /// Retourne le verdict avec la priorité :
    /// SelfProtection > Symlink-resolved > Blocked > ReadOnly > Allowed > Unmatched.
    ///
    /// En mode Paranoid, un chemin Unmatched est traité comme Blocked (default:deny).
    pub fn check(&self, path: &Path, mode: &crate::types::OperationMode) -> PathVerdict {
        // Chemin vide → Unmatched
        if path.as_os_str().is_empty() {
            return PathVerdict::Unmatched;
        }

        // ---------------------------------------------------------------
        // Step 0.4 — Self-protection: ALWAYS blocked, regardless of mode
        // ---------------------------------------------------------------
        let normalized_for_self = Self::normalize(path);
        if Self::matches_self_protection(&normalized_for_self) {
            return PathVerdict::Blocked;
        }

        // ---------------------------------------------------------------
        // Step 1.3 — Symlink detection: resolve symlinks and check the
        // real target against self-protection paths
        // ---------------------------------------------------------------
        if has_symlink_components(path) {
            if let Some(resolved) = resolve_symlink_target(path) {
                let resolved_normalized = Self::normalize(&resolved);
                // Symlink pointing to self-protection → always blocked
                if Self::matches_self_protection(&resolved_normalized) {
                    return PathVerdict::Blocked;
                }
            }
        }

        // Normaliser le chemin : canonicalize si possible, sinon nettoyage basique
        // (canonicalize already follows symlinks on supported platforms)
        let normalized = Self::normalize(path);

        // Double-check: if the normalized path (after canonicalize which follows
        // symlinks) hits self-protection → always blocked
        if Self::matches_self_protection(&normalized) {
            return PathVerdict::Blocked;
        }

        self.check_against_rules(&normalized, mode)
    }

    /// Check a normalized path against user-configured rules (blocked/read_only/allowed).
    fn check_against_rules(
        &self,
        normalized: &Path,
        mode: &crate::types::OperationMode,
    ) -> PathVerdict {
        // Vérifier dans l'ordre de priorité
        if self.matches_list(normalized, &self.blocked, &self.blocked_globs) {
            return PathVerdict::Blocked;
        }
        if self.matches_list(normalized, &self.read_only, &self.read_only_globs) {
            return PathVerdict::ReadOnly;
        }
        if self.matches_list(normalized, &self.allowed, &self.allowed_globs) {
            return PathVerdict::Allowed;
        }

        // Default:deny en mode Paranoid — tout ce qui n'est pas explicitement autorisé est bloqué
        if *mode == crate::types::OperationMode::Paranoid {
            return PathVerdict::Blocked;
        }

        PathVerdict::Unmatched
    }

    /// Checks if a normalized path matches any self-protection path.
    /// Self-protection matching is hierarchical: a file under a protected
    /// directory is also protected.
    fn matches_self_protection(normalized: &Path) -> bool {
        let path_str = normalized.to_string_lossy();
        for sp in SELF_PROTECTION_PATHS {
            // For directory paths (ending with /), use hierarchical matching
            if sp.ends_with('/') {
                if path_str.starts_with(sp) {
                    return true;
                }
                // Also match the directory itself without trailing slash
                let without_slash = sp.trim_end_matches('/');
                if path_str == without_slash {
                    return true;
                }
            } else {
                // Exact file match
                if path_str == *sp {
                    return true;
                }
            }
        }
        false
    }

    /// Normalise un chemin : tente la canonicalisation, sinon nettoyage lexical.
    fn normalize(path: &Path) -> PathBuf {
        // Tenter la canonicalisation (résout symlinks, .., //)
        if let Ok(canonical) = path.canonicalize() {
            return canonical;
        }

        // Fallback : nettoyage lexical des composants
        let mut result = PathBuf::new();
        for component in path.components() {
            match component {
                std::path::Component::ParentDir => {
                    result.pop();
                }
                std::path::Component::CurDir => {}
                _ => {
                    result.push(component);
                }
            }
        }
        result
    }

    /// Vérifie si un chemin normalisé matche une liste (exact + glob).
    /// Le matching hiérarchique est pris en compte : si `/a/b` est dans la liste,
    /// alors `/a/b/c/d` matche aussi.
    fn matches_list(
        &self,
        normalized: &Path,
        exact_paths: &[PathBuf],
        glob_patterns: &[glob::Pattern],
    ) -> bool {
        // Match exact ou hiérarchique (sous-répertoire)
        for blocked_path in exact_paths {
            // Canonicaliser aussi le chemin de la règle
            let rule_path = Self::normalize(blocked_path);

            // Match exact
            if normalized == rule_path {
                return true;
            }

            // Match hiérarchique : le chemin est un enfant du chemin bloqué
            // On vérifie que c'est un vrai sous-répertoire (pas juste un préfixe de nom).
            if normalized.starts_with(&rule_path) {
                return true;
            }
        }

        // Match glob
        let path_str = normalized.to_string_lossy();
        for pattern in glob_patterns {
            if pattern.matches(&path_str) {
                return true;
            }
        }

        false
    }
}

// ---------------------------------------------------------------------------
// Symlink detection and resolution helpers
// ---------------------------------------------------------------------------

/// Checks if any component along the path is a symlink.
/// Walks the path from root downward, checking each prefix.
pub fn has_symlink_components(path: &Path) -> bool {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component);
        // Check if this prefix is a symlink
        if let Ok(metadata) = std::fs::symlink_metadata(&current) {
            if metadata.file_type().is_symlink() {
                return true;
            }
        }
    }
    false
}

/// Resolves a path that may contain symlinks to its final real target.
/// Returns `None` if the path cannot be resolved (e.g., broken symlink).
pub fn resolve_symlink_target(path: &Path) -> Option<PathBuf> {
    // First try direct read_link for simple symlinks
    if let Ok(metadata) = std::fs::symlink_metadata(path) {
        if metadata.file_type().is_symlink() {
            // Use canonicalize to follow the full chain
            return path.canonicalize().ok();
        }
    }

    // For paths with symlink components in the middle, try canonicalize
    // on the longest existing prefix
    let mut current = PathBuf::new();
    let mut remaining_components = Vec::new();
    let mut found_symlink = false;

    for component in path.components() {
        current.push(component);
        if let Ok(metadata) = std::fs::symlink_metadata(&current) {
            if metadata.file_type().is_symlink() {
                found_symlink = true;
                // Resolve this symlink
                if let Ok(resolved) = current.canonicalize() {
                    current = resolved;
                } else {
                    return None;
                }
            }
        } else {
            // Path component doesn't exist yet — collect remaining
            remaining_components.push(component);
        }
    }

    if found_symlink {
        // Append any remaining components to the resolved path
        for comp in remaining_components {
            current.push(comp);
        }
        Some(current)
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// FsGuard — implémentation du Guard trait
// ---------------------------------------------------------------------------

/// Filesystem Guard : surveille les accès fichier et alerte sur les violations.
pub struct FsGuard {
    config: FsGuardConfig,
    running: Arc<AtomicBool>,
    events_total: Arc<AtomicU64>,
    events_blocked: Arc<AtomicU64>,
    start_time: Arc<std::sync::Mutex<Option<chrono::DateTime<Utc>>>>,
}

impl FsGuard {
    /// Crée un nouveau FsGuard à partir de la configuration.
    pub fn new(config: &FsGuardConfig) -> Self {
        Self {
            config: config.clone(),
            running: Arc::new(AtomicBool::new(false)),
            events_total: Arc::new(AtomicU64::new(0)),
            events_blocked: Arc::new(AtomicU64::new(0)),
            start_time: Arc::new(std::sync::Mutex::new(None)),
        }
    }

    /// Détermine l'action à prendre en fonction de la configuration.
    pub fn determine_action(action_str: &str, pid: Option<u32>) -> ActionTaken {
        match action_str {
            "kill_and_alert" => ActionTaken::Killed {
                pid: pid.unwrap_or(0),
            },
            "alert_only" => ActionTaken::Alerted,
            _ => ActionTaken::Logged,
        }
    }

    /// Crée un SecurityEvent pour un accès bloqué.
    pub fn create_blocked_event(path: &Path, event_kind: &str) -> SecurityEvent {
        SecurityEvent::new(
            GuardModule::FsGuard,
            Severity::Critical,
            ActionTaken::Blocked,
            format!(
                "Blocked {} access to protected path: {}",
                event_kind,
                path.display()
            ),
        )
    }

    /// Crée un SecurityEvent pour un write sur un chemin read-only.
    pub fn create_read_only_event(path: &Path, event_kind: &str) -> SecurityEvent {
        SecurityEvent::new(
            GuardModule::FsGuard,
            Severity::Warning,
            ActionTaken::Blocked,
            format!(
                "Blocked {} on read-only path: {}",
                event_kind,
                path.display()
            ),
        )
    }
}

#[async_trait::async_trait]
impl Guard for FsGuard {
    fn name(&self) -> &str {
        "fs_guard"
    }

    async fn start(&self, _alert_tx: mpsc::Sender<SecurityEvent>) -> anyhow::Result<()> {
        self.running.store(true, Ordering::SeqCst);
        *self.start_time.lock().expect("lock poisoned") = Some(Utc::now());

        // Phase 2 MVP : le watcher notify est lancé ici.
        // Pour les tests unitaires, on valide le lifecycle (start/stop/status).
        // L'intégration avec notify sera complétée quand on branche au daemon.

        if self.config.enabled {
            let _matcher = PathMatcher::new(
                self.config.blocked_paths.clone(),
                self.config.read_only_paths.clone(),
                self.config.allowed_paths.clone(),
            );
            // Le watcher serait lancé dans un tokio::task ici
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
