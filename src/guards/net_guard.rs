//! Network Egress Guard — surveille les connexions réseau sortantes.
//!
//! Architecture en 3 couches :
//! 1. **EgressMatcher** (logique pure) : domaine/IP + allowed list → verdict
//! 2. **ConnectionParser** (logique pure) : output lsof → Vec<ConnectionInfo>
//! 3. **NetGuard** (Guard trait) : polling lsof → détection → mpsc

use crate::config::{AppConfig, NetGuardConfig};
use crate::types::{Guard, GuardStatus, SecurityEvent};
use chrono::{Duration, Utc};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

// ---------------------------------------------------------------------------
// EgressVerdict — résultat du matching d'une connexion sortante
// ---------------------------------------------------------------------------

/// Verdict pour une connexion sortante.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EgressVerdict {
    /// La destination est dans la liste autorisée.
    Allowed,
    /// La destination n'est pas dans la liste autorisée.
    Blocked,
}

// ---------------------------------------------------------------------------
// EgressMatcher — logique pure de matching de domaines/IPs
// ---------------------------------------------------------------------------

/// Compare un domaine ou IP de destination contre la liste allowed_egress.
///
/// Matching case-insensitive. Exact match uniquement (pas de wildcard
/// automatique pour les sous-domaines, sauf si configuré explicitement).
pub struct EgressMatcher {
    allowed: Vec<String>,
}

impl EgressMatcher {
    /// Crée un nouveau matcher à partir de la liste de destinations autorisées.
    /// Les domaines sont stockés en lowercase pour le matching case-insensitive.
    pub fn new(allowed_egress: &[String]) -> Self {
        let allowed = allowed_egress.iter().map(|d| d.to_lowercase()).collect();
        Self { allowed }
    }

    /// Vérifie si une destination (domaine ou IP) est autorisée.
    ///
    /// En mode Monitor/Enforce, un domaine non dans la liste est autorisé (log only).
    /// En mode Paranoid, un domaine non dans la liste est bloqué (default:deny).
    pub fn check(&self, destination: &str, mode: &crate::types::OperationMode) -> EgressVerdict {
        if destination.is_empty() {
            return EgressVerdict::Blocked;
        }

        // Normaliser : lowercase, retirer le trailing dot
        let normalized = destination.to_lowercase();
        let normalized = normalized.strip_suffix('.').unwrap_or(&normalized);

        // Vérifier dans la liste autorisée
        for allowed in &self.allowed {
            if normalized == allowed.as_str() {
                return EgressVerdict::Allowed;
            }
        }

        // Destination non dans la liste
        // En Paranoid → default:deny, sinon → permissif
        if *mode == crate::types::OperationMode::Paranoid {
            EgressVerdict::Blocked
        } else {
            EgressVerdict::Allowed
        }
    }

    /// Check if a destination is a raw IP (not a domain name).
    /// In Paranoid mode, raw IP egress that's not in the whitelist triggers an alert.
    pub fn is_raw_ip(destination: &str) -> bool {
        destination.parse::<std::net::IpAddr>().is_ok()
    }
}

// ---------------------------------------------------------------------------
// DnsCache — détection de DNS rebinding
// ---------------------------------------------------------------------------

/// DNS cache for rebinding detection.
/// Tracks domain→IP mappings to detect when a domain suddenly resolves
/// to a different IP, which could indicate a DNS rebinding attack.
pub struct DnsCache {
    /// domain (lowercase) -> first-seen IP
    entries: HashMap<String, String>,
}

impl DnsCache {
    /// Crée un nouveau cache DNS vide.
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// Record a DNS resolution. Returns None if first seen or same IP,
    /// or Some(old_ip) if the IP changed (potential rebinding).
    pub fn record(&mut self, domain: &str, ip: &str) -> Option<String> {
        let domain_lower = domain.to_lowercase();
        if let Some(existing_ip) = self.entries.get(&domain_lower) {
            if existing_ip != ip {
                let old = existing_ip.clone();
                self.entries.insert(domain_lower, ip.to_string());
                return Some(old);
            }
            None
        } else {
            self.entries.insert(domain_lower, ip.to_string());
            None
        }
    }
}

impl Default for DnsCache {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// ConnectionInfo — informations sur une connexion réseau
// ---------------------------------------------------------------------------

/// Informations extraites d'une ligne lsof, enrichies optionnellement par sysinfo.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ConnectionInfo {
    pub pid: u32,
    /// Nom de processus tel que rapporté par lsof (possiblement tronqué à ~15 chars).
    pub process_name: String,
    pub protocol: String,
    pub target_ip: String,
    pub target_port: u16,
    /// Nom complet du processus via sysinfo (non tronqué). None si pas enrichi.
    pub full_process_name: Option<String>,
    /// Ligne de commande complète via sysinfo. None si pas enrichi.
    pub full_cmd: Option<String>,
}

impl ConnectionInfo {
    /// Vérifie si cette connexion correspond à un des patterns watch_processes.
    ///
    /// Matche contre : nom lsof tronqué OU nom sysinfo complet OU cmd sysinfo.
    /// Si watch_processes est vide, matche tout (= pas de filtre).
    pub fn matches_watch_processes(&self, patterns: &[String]) -> bool {
        if patterns.is_empty() {
            return true;
        }

        // Try matching with lsof truncated name
        if crate::process::matches_process_patterns(&self.process_name, "", patterns) {
            return true;
        }

        // Try matching with full sysinfo name
        if let Some(ref full_name) = self.full_process_name {
            if crate::process::matches_process_patterns(full_name, "", patterns) {
                return true;
            }
        }

        // Try matching with full cmd line (regex match against patterns)
        if let Some(ref full_cmd) = self.full_cmd {
            if crate::process::matches_process_patterns("", full_cmd, patterns) {
                return true;
            }
        }

        false
    }
}

// ---------------------------------------------------------------------------
// ConnectionParser — parsing de l'output lsof
// ---------------------------------------------------------------------------

/// Parse la sortie de `lsof -i -n -P` pour extraire les connexions établies.
pub struct ConnectionParser;

impl ConnectionParser {
    /// Parse l'output complet de lsof.
    /// Format attendu : COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
    /// On filtre pour garder uniquement les connexions ESTABLISHED.
    pub fn parse_lsof_output(output: &str) -> Vec<ConnectionInfo> {
        output.lines().filter_map(Self::parse_line).collect()
    }

    /// Parse une seule ligne lsof.
    /// Retourne None si la ligne est un header, LISTEN, ou malformée.
    fn parse_line(line: &str) -> Option<ConnectionInfo> {
        // Ignorer les lignes vides
        if line.trim().is_empty() {
            return None;
        }

        // Ignorer la ligne header
        if line.starts_with("COMMAND") {
            return None;
        }

        // On ne veut que les ESTABLISHED
        if !line.contains("ESTABLISHED") {
            return None;
        }

        // Split par whitespace
        // Format: COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
        // Le champ NAME (dernier) contient l'adresse : local->remote (ESTABLISHED)
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 9 {
            return None;
        }

        let process_name = fields[0].to_string();
        let pid: u32 = fields[1].parse().ok()?;

        // Trouver le champ NAME — c'est le dernier champ avant "(ESTABLISHED)"
        // Format typique : "192.168.1.1:1234->93.184.216.34:443 (ESTABLISHED)"
        // Ou parfois : "192.168.1.1:1234->93.184.216.34:443"
        let name_field = fields.iter().find(|f| f.contains("->"))?;

        // Extraire la partie remote (après ->)
        let remote_part = name_field.split("->").nth(1)?;

        // Séparer IP et port : "93.184.216.34:443"
        // Attention IPv6 : "[::1]:443"
        let (target_ip, target_port) = if remote_part.starts_with('[') {
            // IPv6 : [::1]:443
            let bracket_end = remote_part.find(']')?;
            let ip = &remote_part[1..bracket_end];
            let port_str = &remote_part[bracket_end + 2..]; // skip ]:
            (ip.to_string(), port_str.parse().ok()?)
        } else {
            // IPv4 : 93.184.216.34:443
            let last_colon = remote_part.rfind(':')?;
            let ip = &remote_part[..last_colon];
            let port_str = &remote_part[last_colon + 1..];
            (ip.to_string(), port_str.parse().ok()?)
        };

        // Détecter le protocole (TCP vs UDP) — champ TYPE ou NODE
        let protocol = if fields.contains(&"TCP") {
            "TCP".to_string()
        } else if fields.contains(&"UDP") {
            "UDP".to_string()
        } else {
            "TCP".to_string() // Default
        };

        Some(ConnectionInfo {
            pid,
            process_name,
            protocol,
            target_ip,
            target_port,
            full_process_name: None,
            full_cmd: None,
        })
    }
}

// ---------------------------------------------------------------------------
// NetGuard — implémentation du Guard trait
// ---------------------------------------------------------------------------

/// Network Egress Guard : surveille les connexions réseau sortantes
/// et alerte sur les destinations non autorisées.
pub struct NetGuard {
    config: NetGuardConfig,
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

impl NetGuard {
    /// Crée un nouveau NetGuard à partir de la configuration.
    pub fn new(config: &NetGuardConfig, app_config: Arc<RwLock<AppConfig>>) -> Self {
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
impl Guard for NetGuard {
    fn name(&self) -> &str {
        "net_guard"
    }

    async fn start(&self, alert_tx: mpsc::Sender<SecurityEvent>) -> anyhow::Result<()> {
        self.running.store(true, Ordering::SeqCst);
        *self.start_time.lock().expect("lock poisoned") = Some(Utc::now());

        if self.config.enabled {
            let matcher = EgressMatcher::new(&self.config.allowed_egress);
            let cancel = self.cancel_token.clone();
            let app_config = Arc::clone(&self.app_config);
            let watch_processes = self.config.watch_processes.clone();
            let events_total = Arc::clone(&self.events_total);
            let events_blocked = Arc::clone(&self.events_blocked);
            let poll_interval = std::time::Duration::from_millis(self.config.poll_interval_ms);

            let handle = tokio::spawn(async move {
                let mut seen_connections: HashSet<(u32, String, u16)> = HashSet::new();
                let mut dns_cache = DnsCache::new();
                let mut process_scanner = crate::process::ProcessScanner::new();

                loop {
                    tokio::select! {
                        _ = cancel.cancelled() => {
                            tracing::info!("Net Guard polling shutting down");
                            break;
                        }
                        _ = tokio::time::sleep(poll_interval) => {
                            // Run lsof -i -n -P
                            let output = match tokio::process::Command::new("lsof")
                                .args(["-i", "-n", "-P"])
                                .output()
                                .await
                            {
                                Ok(out) => out,
                                Err(e) => {
                                    tracing::warn!("Failed to run lsof: {}", e);
                                    continue;
                                }
                            };

                            let stdout = String::from_utf8_lossy(&output.stdout);
                            let mut connections = ConnectionParser::parse_lsof_output(&stdout);

                            // Enrich connections with sysinfo data (full name + cmd)
                            // One refresh per cycle, then O(1) lookups per PID
                            process_scanner.refresh();
                            for conn in &mut connections {
                                if let Some(proc_info) = process_scanner.get_by_pid(conn.pid) {
                                    conn.full_process_name = Some(proc_info.name);
                                    conn.full_cmd = Some(proc_info.cmd);
                                }
                            }

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

                            // Filter to watched processes using enriched info
                            let filtered: Vec<&ConnectionInfo> = connections
                                .iter()
                                .filter(|c| c.matches_watch_processes(&watch_processes))
                                .collect();

                            // Prune dead connections (clean seen set if > 10000)
                            if seen_connections.len() > 10_000 {
                                seen_connections.clear();
                            }

                            for conn in filtered {
                                let conn_key = (conn.pid, conn.target_ip.clone(), conn.target_port);

                                // Skip already-seen connections
                                if seen_connections.contains(&conn_key) {
                                    continue;
                                }

                                // Check raw IP alert (paranoid mode only)
                                if EgressMatcher::is_raw_ip(&conn.target_ip)
                                    && mode == crate::types::OperationMode::Paranoid
                                {
                                    seen_connections.insert(conn_key.clone());
                                    events_total.fetch_add(1, Ordering::SeqCst);
                                    events_blocked.fetch_add(1, Ordering::SeqCst);
                                    let event = SecurityEvent::new(
                                        crate::types::GuardModule::NetGuard,
                                        crate::types::Severity::Warning,
                                        crate::types::ActionTaken::Alerted,
                                        format!(
                                            "Raw IP egress detected (pid {} {}): {}:{}",
                                            conn.pid,
                                            conn.process_name,
                                            conn.target_ip,
                                            conn.target_port
                                        ),
                                    );
                                    let _ = alert_tx.try_send(event);
                                    continue;
                                }

                                // DNS rebinding check
                                if let Some(old_ip) = dns_cache.record(&conn.target_ip, &conn.target_ip) {
                                    tracing::warn!(
                                        "DNS rebinding detected: {} changed from {} to {}",
                                        conn.target_ip,
                                        old_ip,
                                        conn.target_ip
                                    );
                                }

                                // Check egress against allowed list
                                let verdict = matcher.check(&conn.target_ip, &mode);
                                if verdict == EgressVerdict::Blocked {
                                    seen_connections.insert(conn_key);
                                    events_total.fetch_add(1, Ordering::SeqCst);
                                    events_blocked.fetch_add(1, Ordering::SeqCst);
                                    let event = SecurityEvent::new(
                                        crate::types::GuardModule::NetGuard,
                                        crate::types::Severity::Warning,
                                        crate::types::ActionTaken::Alerted,
                                        format!(
                                            "Blocked egress (pid {} {}): {}:{} ({})",
                                            conn.pid,
                                            conn.process_name,
                                            conn.target_ip,
                                            conn.target_port,
                                            conn.protocol
                                        ),
                                    );
                                    let _ = alert_tx.try_send(event);
                                } else {
                                    seen_connections.insert(conn_key);
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
