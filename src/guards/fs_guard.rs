//! Filesystem Guard — surveille les accès fichier des processus OpenClaw.
//!
//! Architecture en 3 couches :
//! 1. **PathMatcher** (logique pure) : chemin + règles → verdict
//! 2. **FsEventHandler** (orchestration) : reçoit events notify → filtre → mpsc
//! 3. **FsGuard** (Guard trait) : lifecycle start/stop/status

use crate::config::{expand_tilde, AppConfig, FsGuardConfig};
use crate::types::{ActionTaken, Guard, GuardModule, GuardStatus, SecurityEvent, Severity};
use chrono::{Duration, Utc};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

// ---------------------------------------------------------------------------
// Self-protection paths — always blocked regardless of mode or user config
// ---------------------------------------------------------------------------

/// System-level paths that CounterClaw uses for its own operation.
/// These are ALWAYS blocked to prevent an agent from tampering with the daemon.
/// Matching is hierarchical: any file under these directories is also blocked.
const SYSTEM_PROTECTION_PATHS: &[&str] = &[
    "/etc/counterclaw/",
    "/var/log/counterclaw/",
    "/var/run/counterclaw.pid",
    "/Library/LaunchDaemons/io.counterclaw.daemon.plist",
    "/usr/local/bin/counterclaw",
];

/// Returns the complete list of self-protection paths (system + user-mode).
///
/// V3: Includes ~/.counterclaw/ to protect user-mode config, logs, and API token.
/// The user home directory is resolved at runtime.
pub fn get_self_protection_paths() -> Vec<String> {
    let mut paths: Vec<String> = SYSTEM_PROTECTION_PATHS
        .iter()
        .map(|s| s.to_string())
        .collect();

    // Add user-mode paths (V3: protect ~/.counterclaw/)
    if let Some(home) = dirs::home_dir() {
        let user_dir = home.join(".counterclaw");
        // Add with trailing slash for hierarchical matching
        paths.push(format!("{}/", user_dir.display()));
    }

    paths
}

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
    /// V3: Uses get_self_protection_paths() for both system and user-mode paths.
    fn matches_self_protection(normalized: &Path) -> bool {
        let path_str = normalized.to_string_lossy();
        let protection_paths = get_self_protection_paths();
        for sp in &protection_paths {
            // For directory paths (ending with /), use hierarchical matching
            if sp.ends_with('/') {
                if path_str.starts_with(sp.as_str()) {
                    return true;
                }
                // Also match the directory itself without trailing slash
                let without_slash = sp.trim_end_matches('/');
                if *path_str == *without_slash {
                    return true;
                }
            } else {
                // Exact file match
                if *path_str == *sp {
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
    /// V4: Sur macOS, le matching est case-insensitive (APFS est case-insensitive).
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

            // V4: On macOS, compare case-insensitively
            #[cfg(target_os = "macos")]
            {
                let norm_lower = normalized.to_string_lossy().to_lowercase();
                let rule_lower = rule_path.to_string_lossy().to_lowercase();

                // Match exact (case-insensitive)
                if norm_lower == rule_lower {
                    return true;
                }

                // Match hiérarchique (case-insensitive)
                if norm_lower.starts_with(&rule_lower)
                    && (rule_lower.ends_with('/')
                        || norm_lower.as_bytes().get(rule_lower.len()) == Some(&b'/'))
                {
                    return true;
                }
            }

            #[cfg(not(target_os = "macos"))]
            {
                // Match exact
                if normalized == rule_path {
                    return true;
                }

                // Match hiérarchique
                if normalized.starts_with(&rule_path) {
                    return true;
                }
            }
        }

        // Match glob
        // V4: Sur macOS, utiliser case-insensitive matching
        let path_str = normalized.to_string_lossy();
        #[cfg(target_os = "macos")]
        let match_options = glob::MatchOptions {
            case_sensitive: false,
            ..Default::default()
        };

        for pattern in glob_patterns {
            #[cfg(target_os = "macos")]
            {
                if pattern.matches_with(&path_str, match_options) {
                    return true;
                }
            }
            #[cfg(not(target_os = "macos"))]
            {
                if pattern.matches(&path_str) {
                    return true;
                }
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
    /// V13: Watchdog — tracks the last time an event was processed.
    /// Used to detect if the notify watcher has stalled.
    last_activity: Arc<std::sync::Mutex<Option<std::time::Instant>>>,
    cancel_token: CancellationToken,
    task_handle: Arc<tokio::sync::Mutex<Option<tokio::task::JoinHandle<()>>>>,
    /// Shared config for hot-reload and mode access (used in start() I/O layer).
    #[allow(dead_code)]
    app_config: Arc<RwLock<AppConfig>>,
}

impl FsGuard {
    /// Crée un nouveau FsGuard à partir de la configuration.
    pub fn new(config: &FsGuardConfig, app_config: Arc<RwLock<AppConfig>>) -> Self {
        Self {
            config: config.clone(),
            running: Arc::new(AtomicBool::new(false)),
            events_total: Arc::new(AtomicU64::new(0)),
            events_blocked: Arc::new(AtomicU64::new(0)),
            start_time: Arc::new(std::sync::Mutex::new(None)),
            last_activity: Arc::new(std::sync::Mutex::new(None)),
            cancel_token: CancellationToken::new(),
            task_handle: Arc::new(tokio::sync::Mutex::new(None)),
            app_config,
        }
    }

    /// V13: Checks if the watchdog is healthy.
    ///
    /// Returns true if:
    /// - The guard is not running (no watchdog needed)
    /// - The guard has not been running long enough (grace period)
    /// - The last activity was within the watchdog timeout (300s default)
    pub fn is_watchdog_healthy(&self) -> bool {
        if !self.running.load(Ordering::SeqCst) {
            return true;
        }
        let activity = self.last_activity.lock().expect("watchdog lock");
        match *activity {
            Some(last) => last.elapsed().as_secs() < 300,
            None => true, // No activity yet — still in grace period
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

    async fn start(&self, alert_tx: mpsc::Sender<SecurityEvent>) -> anyhow::Result<()> {
        self.running.store(true, Ordering::SeqCst);
        *self.start_time.lock().expect("lock poisoned") = Some(Utc::now());
        // V13: Initialize watchdog timestamp at start
        *self.last_activity.lock().expect("watchdog lock") = Some(std::time::Instant::now());

        if self.config.enabled {
            let matcher = PathMatcher::new(
                self.config.blocked_paths.clone(),
                self.config.read_only_paths.clone(),
                self.config.allowed_paths.clone(),
            );

            // Collect paths to watch (blocked + read_only)
            let mut watch_paths: Vec<PathBuf> = Vec::new();
            for p in self
                .config
                .blocked_paths
                .iter()
                .chain(self.config.read_only_paths.iter())
            {
                let expanded = expand_tilde(p);
                // Skip glob patterns — we can only watch real directories
                let expanded_str = expanded.to_string_lossy();
                if expanded_str.contains('*')
                    || expanded_str.contains('?')
                    || expanded_str.contains('[')
                {
                    continue;
                }
                watch_paths.push(expanded);
            }

            // Bridge notify → async via mpsc channel
            let (notify_tx, mut notify_rx) = tokio::sync::mpsc::channel::<notify::Event>(256);

            // Create the notify watcher
            let watcher_result =
                notify::recommended_watcher(move |res: Result<notify::Event, notify::Error>| {
                    if let Ok(event) = res {
                        let _ = notify_tx.blocking_send(event);
                    }
                });

            let mut watcher = match watcher_result {
                Ok(w) => w,
                Err(e) => {
                    tracing::warn!("Failed to create filesystem watcher: {}", e);
                    return Ok(());
                }
            };

            // Register paths with the watcher
            use notify::Watcher;
            for path in &watch_paths {
                if path.exists() {
                    if let Err(e) = watcher.watch(path, notify::RecursiveMode::Recursive) {
                        tracing::warn!("Failed to watch {}: {}", path.display(), e);
                    } else {
                        tracing::info!("FS Guard watching: {}", path.display());
                    }
                } else {
                    tracing::warn!(
                        "FS Guard: path does not exist, skipping: {}",
                        path.display()
                    );
                }
            }

            let cancel = self.cancel_token.clone();
            let app_config = Arc::clone(&self.app_config);
            let events_total = Arc::clone(&self.events_total);
            let events_blocked = Arc::clone(&self.events_blocked);
            let last_activity = Arc::clone(&self.last_activity);

            let handle = tokio::spawn(async move {
                // Keep watcher alive for the duration of the task
                let _watcher = watcher;

                loop {
                    tokio::select! {
                        _ = cancel.cancelled() => {
                            tracing::info!("FS Guard watcher shutting down");
                            break;
                        }
                        event = notify_rx.recv() => {
                            let event = match event {
                                Some(e) => e,
                                None => break, // Channel closed
                            };

                            // Update watchdog
                            if let Ok(mut ts) = last_activity.lock() {
                                *ts = Some(std::time::Instant::now());
                            }

                            // Determine if this is a write-type event
                            let is_write = matches!(
                                event.kind,
                                notify::EventKind::Create(_)
                                    | notify::EventKind::Modify(_)
                                    | notify::EventKind::Remove(_)
                            );

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

                            // Check each affected path
                            for path in &event.paths {
                                let verdict = matcher.check(path, &mode);

                                events_total.fetch_add(1, Ordering::SeqCst);

                                match verdict {
                                    PathVerdict::Blocked => {
                                        events_blocked.fetch_add(1, Ordering::SeqCst);
                                        let event_kind = format!("{:?}", event.kind);
                                        let se = FsGuard::create_blocked_event(path, &event_kind);
                                        let _ = alert_tx.try_send(se);
                                    }
                                    PathVerdict::ReadOnly if is_write => {
                                        events_blocked.fetch_add(1, Ordering::SeqCst);
                                        let event_kind = format!("{:?}", event.kind);
                                        let se = FsGuard::create_read_only_event(path, &event_kind);
                                        let _ = alert_tx.try_send(se);
                                    }
                                    _ => {
                                        // Allowed or Unmatched or ReadOnly+Read → ignore
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
