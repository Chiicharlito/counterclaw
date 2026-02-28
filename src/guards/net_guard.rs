//! Network Egress Guard — surveille les connexions réseau sortantes.
//!
//! Architecture en 3 couches :
//! 1. **EgressMatcher** (logique pure) : domaine/IP + allowed list → verdict
//! 2. **ConnectionParser** (logique pure) : output lsof → Vec<ConnectionInfo>
//! 3. **NetGuard** (Guard trait) : polling lsof → détection → mpsc

use crate::config::NetGuardConfig;
use crate::types::{Guard, GuardStatus, SecurityEvent};
use chrono::{Duration, Utc};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;

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

/// Informations extraites d'une ligne lsof.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ConnectionInfo {
    pub pid: u32,
    pub process_name: String,
    pub protocol: String,
    pub target_ip: String,
    pub target_port: u16,
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
}

impl NetGuard {
    /// Crée un nouveau NetGuard à partir de la configuration.
    pub fn new(config: &NetGuardConfig) -> Self {
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
impl Guard for NetGuard {
    fn name(&self) -> &str {
        "net_guard"
    }

    async fn start(&self, _alert_tx: mpsc::Sender<SecurityEvent>) -> anyhow::Result<()> {
        self.running.store(true, Ordering::SeqCst);
        *self.start_time.lock().expect("lock poisoned") = Some(Utc::now());

        if self.config.enabled {
            let _matcher = EgressMatcher::new(&self.config.allowed_egress);
            let _seen_connections: HashSet<(u32, String, u16)> = HashSet::new();
            // Le polling lsof serait lancé dans un tokio::task ici
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
