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
/// Priorité : Blocked > ReadOnly > Allowed > Unmatched.
///
/// Gère :
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
    /// Retourne le verdict avec la priorité : Blocked > ReadOnly > Allowed > Unmatched.
    pub fn check(&self, path: &Path) -> PathVerdict {
        // Chemin vide → Unmatched
        if path.as_os_str().is_empty() {
            return PathVerdict::Unmatched;
        }

        // Normaliser le chemin : canonicalize si possible, sinon nettoyage basique
        let normalized = Self::normalize(path);

        // Vérifier dans l'ordre de priorité
        if self.matches_list(&normalized, &self.blocked, &self.blocked_globs) {
            return PathVerdict::Blocked;
        }
        if self.matches_list(&normalized, &self.read_only, &self.read_only_globs) {
            return PathVerdict::ReadOnly;
        }
        if self.matches_list(&normalized, &self.allowed, &self.allowed_globs) {
            return PathVerdict::Allowed;
        }

        PathVerdict::Unmatched
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
