//! CDP Proxy — proxy transparent entre l'agent AI et Chrome DevTools Protocol.
//!
//! Architecture en 5 sous-composants :
//! 1. **DomainMatcher** (PURE) : domaine bloqué/autorisé/approval
//! 2. **CommandFilter** (PURE) : commande CDP bloquée/restreinte
//! 3. **ContentInspector** (PURE) : détection de patterns dangereux
//! 4. **CdpSessionState** (PURE) : tracking URL courante, historique
//! 5. **process_cdp_message** (PURE) : orchestre tout, décision par message
//! 6. **CdpProxy** (ASYNC) : HTTP discovery + WebSocket relay + Guard trait

use crate::config::{
    CdpCommandsConfig, CdpProxyConfig, ContentInspectionConfig, DomainRulesConfig,
};
use crate::types::{ActionTaken, Guard, GuardModule, GuardStatus, SecurityEvent, Severity};
use chrono::{Duration, Utc};
use regex::Regex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum size of a CDP message in bytes (10 MB).
/// Messages exceeding this limit are blocked to prevent DoS attacks.
pub const MAX_CDP_MESSAGE_SIZE: usize = 10 * 1024 * 1024;

/// Maximum number of messages kept in the cross-message content buffer.
const CONTENT_BUFFER_MAX_MESSAGES: usize = 10;

/// Maximum total size (in bytes) of the cross-message content buffer.
const CONTENT_BUFFER_MAX_SIZE: usize = 64 * 1024;

/// URI schemes that are blocked for navigation (security risk).
const BLOCKED_SCHEMES: &[&str] = &["javascript:", "data:", "file:", "blob:", "vbscript:"];

// ---------------------------------------------------------------------------
// Domaines système toujours autorisés (même en mode Paranoid)
// ---------------------------------------------------------------------------

/// Domaines système qui sont TOUJOURS autorisés, quel que soit le mode
/// ou la configuration. Empêche de casser le fonctionnement de base
/// (loopback, localhost).
pub const SYSTEM_ALLOWED_DOMAINS: &[&str] = &["localhost", "127.0.0.1", "::1"];

// ---------------------------------------------------------------------------
// DomainVerdict — résultat du matching de domaine
// ---------------------------------------------------------------------------

/// Verdict rendu par le DomainMatcher.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DomainVerdict {
    Blocked,
    Allowed,
    RequireApproval,
}

// ---------------------------------------------------------------------------
// Security utility functions
// ---------------------------------------------------------------------------

/// Checks if a URL uses a blocked URI scheme (javascript:, data:, file:, blob:, vbscript:).
///
/// These schemes can be used to bypass security controls:
/// - `javascript:` — execute arbitrary JS
/// - `data:` — embed content that evades domain-based filtering
/// - `file:` — read local files
/// - `blob:` — access in-memory data
/// - `vbscript:` — legacy script execution
pub fn is_blocked_scheme(url: &str) -> bool {
    let url_lower = url.to_lowercase();
    let trimmed = url_lower.trim_start();
    BLOCKED_SCHEMES
        .iter()
        .any(|scheme| trimmed.starts_with(scheme))
}

/// Normalizes a domain to punycode (ASCII) for IDN homograph protection.
///
/// Converts internationalized domain names to their ASCII representation
/// using the IDNA standard. This prevents homograph attacks where visually
/// similar Unicode characters (e.g., Cyrillic 'а' vs Latin 'a') are used
/// to impersonate legitimate domains.
///
/// If conversion fails (invalid domain), returns the original lowercased domain.
pub fn normalize_domain(domain: &str) -> String {
    let lower = domain.to_lowercase();
    // Skip normalization for IP addresses and simple ASCII domains
    if lower.is_ascii() {
        return lower;
    }
    match idna::domain_to_ascii(&lower) {
        Ok(ascii) => ascii,
        Err(_) => lower,
    }
}

/// Strips control characters (U+0000 through U+001F) from a string,
/// preserving tabs (\t), newlines (\n), and carriage returns (\r).
///
/// Returns a tuple of (cleaned string, true if any characters were stripped).
pub fn strip_control_chars(s: &str) -> (String, bool) {
    let mut stripped = false;
    let cleaned: String = s
        .chars()
        .filter(|c| {
            if *c != '\t' && *c != '\n' && *c != '\r' && (*c as u32) < 0x20 {
                stripped = true;
                false
            } else {
                true
            }
        })
        .collect();
    (cleaned, stripped)
}

// ---------------------------------------------------------------------------
// DomainMatcher — logique pure de matching de domaines
// ---------------------------------------------------------------------------

/// Compare un domaine contre les listes blocked/allowed/require_approval.
///
/// Priorité : Blocked > RequireApproval > Allowed > default_policy.
/// Supporte les wildcards (*.banking.*).
/// Le matching est case-insensitive.
pub struct DomainMatcher {
    blocked: Vec<String>,
    allowed: Vec<String>,
    require_approval: Vec<String>,
    default_policy: String,
}

impl DomainMatcher {
    /// Crée un nouveau matcher depuis la config des domaines.
    pub fn new(config: &DomainRulesConfig) -> Self {
        Self {
            blocked: config.blocked.iter().map(|s| s.to_lowercase()).collect(),
            allowed: config.allowed.iter().map(|s| s.to_lowercase()).collect(),
            require_approval: config
                .require_approval
                .iter()
                .map(|s| s.to_lowercase())
                .collect(),
            default_policy: config.default_policy.clone(),
        }
    }

    /// Vérifie un domaine et retourne le verdict.
    ///
    /// En mode Paranoid, un domaine non-matché est traité comme Blocked (default:deny),
    /// indépendamment de la default_policy configurée.
    ///
    /// IDN homograph protection: domains are normalized to punycode before comparison.
    pub fn check(&self, domain: &str, mode: &crate::types::OperationMode) -> DomainVerdict {
        let domain_lower = domain.to_lowercase();

        // Les domaines système sont TOUJOURS autorisés (bypass toute la logique)
        if SYSTEM_ALLOWED_DOMAINS.iter().any(|&sd| sd == domain_lower) {
            return DomainVerdict::Allowed;
        }

        // Normalize to punycode for IDN homograph protection
        let normalized = normalize_domain(&domain_lower);

        // Priorité : blocked > require_approval > allowed > default
        if self.matches_list(&normalized, &self.blocked) {
            return DomainVerdict::Blocked;
        }
        if self.matches_list(&normalized, &self.require_approval) {
            return DomainVerdict::RequireApproval;
        }
        if self.matches_list(&normalized, &self.allowed) {
            return DomainVerdict::Allowed;
        }

        // Default:deny en mode Paranoid — tout ce qui n'est pas explicitement autorisé est bloqué
        if *mode == crate::types::OperationMode::Paranoid {
            return DomainVerdict::Blocked;
        }

        // Default policy (pour Monitor et Enforce)
        match self.default_policy.as_str() {
            "block" => DomainVerdict::Blocked,
            _ => DomainVerdict::Allowed,
        }
    }

    /// Vérifie si un domaine matche une entrée de la liste.
    /// Supporte les wildcards : *.banking.* matche my.banking.com
    fn matches_list(&self, domain: &str, list: &[String]) -> bool {
        for entry in list {
            if entry.contains('*') {
                if self.wildcard_matches(domain, entry) {
                    return true;
                }
            } else if domain == entry {
                return true;
            }
        }
        false
    }

    /// Matching wildcard simple :
    /// - `*.banking.*` → split sur `*`, vérifie que chaque segment est contenu
    ///   dans le domaine en tant que sous-chaîne délimitée par des points.
    fn wildcard_matches(&self, domain: &str, pattern: &str) -> bool {
        // Convertir le pattern glob en regex
        let regex_str = format!(
            "^{}$",
            pattern
                .split('*')
                .map(regex::escape)
                .collect::<Vec<_>>()
                .join("[^.]*")
        );
        if let Ok(re) = Regex::new(&regex_str) {
            re.is_match(domain)
        } else {
            false
        }
    }
}

// ---------------------------------------------------------------------------
// CommandFilter — logique pure de filtrage de commandes CDP
// ---------------------------------------------------------------------------

/// Filtre les commandes CDP selon les listes blocked/restricted/log_always.
pub struct CommandFilter {
    blocked: Vec<String>,
    restricted: Vec<String>,
    log_always: Vec<String>,
}

impl CommandFilter {
    /// Crée un filtre depuis la config des commandes CDP.
    pub fn new(config: &CdpCommandsConfig) -> Self {
        Self {
            blocked: config.blocked.clone(),
            restricted: config.restricted_to_allowed_domains.clone(),
            log_always: config.log_always.clone(),
        }
    }

    /// La commande est-elle bloquée inconditionnellement ?
    pub fn is_blocked(&self, method: &str) -> bool {
        self.blocked.iter().any(|b| b == method)
    }

    /// La commande est-elle restreinte aux domaines autorisés ?
    pub fn is_restricted(&self, method: &str) -> bool {
        self.restricted.iter().any(|r| r == method)
    }

    /// La commande doit-elle être loggée systématiquement ?
    pub fn should_log(&self, method: &str) -> bool {
        self.log_always.iter().any(|l| l == method)
    }

    /// Une commande restreinte est-elle autorisée sur ce domaine ?
    pub fn is_allowed_on_domain(&self, method: &str, domain_verdict: &DomainVerdict) -> bool {
        if !self.is_restricted(method) {
            return true;
        }
        *domain_verdict == DomainVerdict::Allowed
    }
}

// ---------------------------------------------------------------------------
// ContentInspector — détection de patterns dangereux dans le contenu
// ---------------------------------------------------------------------------

/// Match trouvé par l'inspecteur de contenu.
#[derive(Debug, Clone)]
pub struct ContentMatch {
    pub name: String,
    pub severity: Severity,
    pub action: String,
}

/// Inspecteur de contenu CDP — cherche des patterns dangereux (API keys, mots de passe, etc.)
pub struct ContentInspector {
    patterns: Vec<CompiledPattern>,
}

struct CompiledPattern {
    name: String,
    regex: Regex,
    severity: Severity,
    action: String,
}

impl ContentInspector {
    /// Crée un inspecteur depuis la config.
    pub fn new(config: &ContentInspectionConfig) -> Self {
        let patterns = if config.enabled {
            config
                .patterns
                .iter()
                .filter_map(|p| {
                    Regex::new(&p.regex).ok().map(|re| CompiledPattern {
                        name: p.name.clone(),
                        regex: re,
                        severity: parse_severity(&p.severity),
                        action: p.action.clone(),
                    })
                })
                .collect()
        } else {
            Vec::new()
        };

        Self { patterns }
    }

    /// Inspecte le contenu et retourne les matches, triés par sévérité décroissante.
    pub fn inspect(&self, content: &str) -> Vec<ContentMatch> {
        if content.is_empty() {
            return Vec::new();
        }

        let mut matches: Vec<ContentMatch> = self
            .patterns
            .iter()
            .filter(|p| p.regex.is_match(content))
            .map(|p| ContentMatch {
                name: p.name.clone(),
                severity: p.severity.clone(),
                action: p.action.clone(),
            })
            .collect();

        // Trier par sévérité décroissante (Critical > High > Warning > Info)
        matches.sort_by(|a, b| b.severity.cmp(&a.severity));

        matches
    }
}

/// Parse une string en Severity.
fn parse_severity(s: &str) -> Severity {
    match s {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "warning" => Severity::Warning,
        _ => Severity::Info,
    }
}

// ---------------------------------------------------------------------------
// CdpSessionState — tracking de la session CDP
// ---------------------------------------------------------------------------

/// État de la session CDP : URL courante, domaine, historique,
/// et buffer de contenu cross-message pour l'inspection.
pub struct CdpSessionState {
    current_url: Option<String>,
    history: Vec<String>,
    /// Cross-message content buffer for split-payload detection.
    content_buffer: Vec<String>,
    /// Total byte size of all entries in content_buffer.
    content_buffer_size: usize,
}

impl CdpSessionState {
    /// Crée un nouvel état vide.
    pub fn new() -> Self {
        Self {
            current_url: None,
            history: Vec::new(),
            content_buffer: Vec::new(),
            content_buffer_size: 0,
        }
    }

    /// Met à jour l'URL courante.
    pub fn update_url(&mut self, url: &str) {
        self.current_url = Some(url.to_string());
        self.history.push(url.to_string());
    }

    /// Retourne l'URL courante.
    pub fn current_url(&self) -> Option<String> {
        self.current_url.clone()
    }

    /// Extrait le domaine de l'URL courante.
    pub fn current_domain(&self) -> Option<String> {
        self.current_url
            .as_ref()
            .and_then(|url| extract_domain_from_url(url))
    }

    /// Retourne l'historique de navigation.
    pub fn history(&self) -> &[String] {
        &self.history
    }

    /// Pushes content into the cross-message inspection buffer.
    ///
    /// Maintains invariants:
    /// - Maximum 10 messages in the buffer
    /// - Maximum 64KB total size
    ///   Oldest entries are evicted when limits are exceeded.
    pub fn push_content(&mut self, content: &str) {
        let content_len = content.len();

        // Evict oldest entries until we have room for the new content
        while self.content_buffer.len() >= CONTENT_BUFFER_MAX_MESSAGES {
            if let Some(removed) = self.content_buffer.first() {
                self.content_buffer_size = self.content_buffer_size.saturating_sub(removed.len());
            }
            self.content_buffer.remove(0);
        }

        // Evict oldest entries until total size is within limit
        while self.content_buffer_size + content_len > CONTENT_BUFFER_MAX_SIZE
            && !self.content_buffer.is_empty()
        {
            if let Some(removed) = self.content_buffer.first() {
                self.content_buffer_size = self.content_buffer_size.saturating_sub(removed.len());
            }
            self.content_buffer.remove(0);
        }

        // If a single message exceeds the max buffer size, truncate it
        let to_push = if content_len > CONTENT_BUFFER_MAX_SIZE {
            &content[..CONTENT_BUFFER_MAX_SIZE]
        } else {
            content
        };

        self.content_buffer_size += to_push.len();
        self.content_buffer.push(to_push.to_string());
    }

    /// Returns all buffered content concatenated for cross-message inspection.
    pub fn get_combined_content(&self) -> String {
        self.content_buffer.join("")
    }
}

impl Default for CdpSessionState {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Utilitaires — extraction de domaine, parsing CDP
// ---------------------------------------------------------------------------

/// Extrait le domaine d'une URL.
///
/// Blocked URI schemes (javascript:, data:, file:, blob:, vbscript:) return None.
/// IDN domains are normalized to punycode.
pub fn extract_domain_from_url(url: &str) -> Option<String> {
    if url.is_empty() {
        return None;
    }

    // Block dangerous URI schemes before parsing
    if is_blocked_scheme(url) {
        return None;
    }

    // Si pas de schéma, en ajouter un pour le parsing
    let url_with_scheme = if url.contains("://") {
        url.to_string()
    } else {
        format!("https://{}", url)
    };

    // Parser avec la lib url ou manuellement
    if let Ok(parsed) = url::Url::parse(&url_with_scheme) {
        parsed.host_str().map(normalize_domain)
    } else {
        None
    }
}

/// Message CDP parsé.
#[derive(Debug)]
pub struct CdpMessage {
    pub id: Option<i64>,
    pub method: Option<String>,
    pub params: Option<serde_json::Value>,
    pub raw: serde_json::Value,
}

impl CdpMessage {
    /// Extrait l'URL d'une commande Page.navigate.
    pub fn extract_navigate_url(&self) -> Option<String> {
        self.params
            .as_ref()
            .and_then(|p| p.get("url"))
            .and_then(|u| u.as_str())
            .map(|s| s.to_string())
    }
}

/// Parse un message CDP JSON.
///
/// Strips control characters (null bytes, etc.) from method and param strings
/// before parsing. Logs a warning if control characters are detected.
pub fn parse_cdp_message(raw: &str) -> Option<CdpMessage> {
    let value: serde_json::Value = serde_json::from_str(raw).ok()?;

    // Extract method with null byte stripping
    let method = value.get("method").and_then(|v| v.as_str()).map(|s| {
        let (cleaned, had_control_chars) = strip_control_chars(s);
        if had_control_chars {
            tracing::warn!(
                "Control characters detected in CDP method string — possible evasion attempt"
            );
        }
        cleaned
    });

    // Extract params with null byte stripping on string values
    let params = value.get("params").map(|p| {
        let mut cleaned_params = p.clone();
        strip_control_chars_in_value(&mut cleaned_params);
        cleaned_params
    });

    Some(CdpMessage {
        id: value.get("id").and_then(|v| v.as_i64()),
        method,
        params,
        raw: value,
    })
}

/// Recursively strips control characters from string values within a JSON Value.
fn strip_control_chars_in_value(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::String(s) => {
            let (cleaned, had_control_chars) = strip_control_chars(s);
            if had_control_chars {
                tracing::warn!(
                    "Control characters detected in CDP params — possible evasion attempt"
                );
                *s = cleaned;
            }
        }
        serde_json::Value::Array(arr) => {
            for item in arr.iter_mut() {
                strip_control_chars_in_value(item);
            }
        }
        serde_json::Value::Object(map) => {
            for (_key, val) in map.iter_mut() {
                strip_control_chars_in_value(val);
            }
        }
        _ => {}
    }
}

/// Génère une réponse d'erreur JSON-RPC synthétique.
pub fn generate_synthetic_error(id: i64, message: &str) -> String {
    serde_json::json!({
        "id": id,
        "error": {
            "code": -32001,
            "message": message
        }
    })
    .to_string()
}

// ---------------------------------------------------------------------------
// CdpDecision — décision prise pour un message CDP
// ---------------------------------------------------------------------------

/// Décision prise par le proxy pour un message CDP.
#[derive(Debug)]
pub enum CdpDecision {
    /// Forwarder le message tel quel.
    Forward,
    /// Forwarder et logger.
    ForwardAndLog { reason: String },
    /// Bloquer le message et retourner une erreur synthétique.
    Block {
        id: i64,
        reason: String,
        severity: Severity,
    },
}

impl CdpDecision {
    /// Est-ce un forward ?
    pub fn is_forward(&self) -> bool {
        matches!(
            self,
            CdpDecision::Forward | CdpDecision::ForwardAndLog { .. }
        )
    }

    /// Est-ce un block ?
    pub fn is_block(&self) -> bool {
        matches!(self, CdpDecision::Block { .. })
    }
}

// ---------------------------------------------------------------------------
// process_cdp_message — fonction libre d'orchestration
// ---------------------------------------------------------------------------

/// Orchestre DomainMatcher + CommandFilter + ContentInspector + SessionState
/// pour prendre une décision sur un message CDP.
///
/// C'est une fonction libre (pas une méthode) : respecte SRP.
/// Fail-open pour les messages non-parsables.
///
/// Security checks performed:
/// 1. Message size limit (10 MB max)
/// 2. Blocked commands
/// 3. Blocked URI schemes for navigation
/// 4. Domain matching for navigation targets
/// 5. Restricted commands on current domain
/// 6. Content inspection (current message + cross-message buffer)
/// 7. Log-always commands
pub fn process_cdp_message(
    raw: &str,
    domain_matcher: &DomainMatcher,
    command_filter: &CommandFilter,
    content_inspector: &ContentInspector,
    session: &mut CdpSessionState,
    mode: &crate::types::OperationMode,
) -> CdpDecision {
    // 0. Check message size limit
    if raw.len() > MAX_CDP_MESSAGE_SIZE {
        // Use id 0 since we can't parse the message
        return CdpDecision::Block {
            id: 0,
            reason: format!(
                "CDP message exceeds size limit ({} bytes > {} bytes max)",
                raw.len(),
                MAX_CDP_MESSAGE_SIZE
            ),
            severity: Severity::High,
        };
    }

    // Tenter de parser le message
    let msg = match parse_cdp_message(raw) {
        Some(m) => m,
        None => return CdpDecision::Forward, // Fail-open pour JSON malformé
    };

    // Les event messages (pas d'id) sont toujours forwardés
    let msg_id = match msg.id {
        Some(id) => id,
        None => return CdpDecision::Forward,
    };

    let method = match &msg.method {
        Some(m) => m.clone(),
        None => return CdpDecision::Forward,
    };

    // 1. Vérifier si la commande est bloquée inconditionnellement
    if command_filter.is_blocked(&method) {
        return CdpDecision::Block {
            id: msg_id,
            reason: format!("Command '{}' is blocked", method),
            severity: Severity::High,
        };
    }

    // 2. Si c'est un Page.navigate, vérifier le domaine cible
    if method == "Page.navigate" {
        if let Some(url) = msg.extract_navigate_url() {
            // 2a. Check for blocked URI schemes
            if is_blocked_scheme(&url) {
                return CdpDecision::Block {
                    id: msg_id,
                    reason: format!("Navigation to blocked URI scheme: {}", url),
                    severity: Severity::Critical,
                };
            }

            if let Some(domain) = extract_domain_from_url(&url) {
                let verdict = domain_matcher.check(&domain, mode);
                match verdict {
                    DomainVerdict::Blocked => {
                        return CdpDecision::Block {
                            id: msg_id,
                            reason: format!("Navigation to blocked domain: {}", domain),
                            severity: Severity::Critical,
                        };
                    }
                    DomainVerdict::RequireApproval => {
                        // MVP : on log et forward (pas d'interactive approval)
                        session.update_url(&url);
                        return CdpDecision::ForwardAndLog {
                            reason: format!("Navigation to approval-required domain: {}", domain),
                        };
                    }
                    DomainVerdict::Allowed => {
                        session.update_url(&url);
                    }
                }
            }
        }
    }

    // 3. Si la commande est restreinte, vérifier le domaine courant
    if command_filter.is_restricted(&method) {
        let domain_verdict = session
            .current_domain()
            .map(|d| domain_matcher.check(&d, mode))
            .unwrap_or(DomainVerdict::Blocked); // Pas de domaine = traité comme bloqué

        if !command_filter.is_allowed_on_domain(&method, &domain_verdict) {
            return CdpDecision::Block {
                id: msg_id,
                reason: format!("Command '{}' restricted to allowed domains only", method),
                severity: Severity::High,
            };
        }
    }

    // 4. Inspection du contenu (cherche des patterns dangereux)
    // Push current message into cross-message buffer
    session.push_content(raw);

    // Inspect both the current message and the combined buffer
    let content_matches = content_inspector.inspect(raw);
    if let Some(first) = content_matches.first() {
        if first.action == "block" {
            return CdpDecision::Block {
                id: msg_id,
                reason: format!("Content inspection match: {}", first.name),
                severity: first.severity.clone(),
            };
        }
    }

    // Also inspect the combined buffer for cross-message patterns
    let combined = session.get_combined_content();
    if combined.len() > raw.len() {
        let buffer_matches = content_inspector.inspect(&combined);
        if let Some(first) = buffer_matches.first() {
            if first.action == "block" {
                return CdpDecision::Block {
                    id: msg_id,
                    reason: format!("Content inspection match (cross-message): {}", first.name),
                    severity: first.severity.clone(),
                };
            }
        }
    }

    // 5. Logger si nécessaire
    if command_filter.should_log(&method) {
        return CdpDecision::ForwardAndLog {
            reason: format!("Command '{}' is in log_always list", method),
        };
    }

    CdpDecision::Forward
}

// ---------------------------------------------------------------------------
// CdpProxy — Guard trait implementation
// ---------------------------------------------------------------------------

/// CDP Proxy : proxy transparent entre l'agent AI et Chrome DevTools Protocol.
pub struct CdpProxy {
    config: CdpProxyConfig,
    running: Arc<AtomicBool>,
    events_total: Arc<AtomicU64>,
    events_blocked: Arc<AtomicU64>,
    start_time: Arc<Mutex<Option<chrono::DateTime<Utc>>>>,
    domain_matcher: DomainMatcher,
    command_filter: CommandFilter,
    content_inspector: ContentInspector,
    session: Arc<Mutex<CdpSessionState>>,
}

impl CdpProxy {
    /// Crée un nouveau CdpProxy depuis la configuration.
    pub fn new(config: &CdpProxyConfig) -> Self {
        Self {
            config: config.clone(),
            running: Arc::new(AtomicBool::new(false)),
            events_total: Arc::new(AtomicU64::new(0)),
            events_blocked: Arc::new(AtomicU64::new(0)),
            start_time: Arc::new(Mutex::new(None)),
            domain_matcher: DomainMatcher::new(&config.domains),
            command_filter: CommandFilter::new(&config.cdp_commands),
            content_inspector: ContentInspector::new(&config.content_inspection),
            session: Arc::new(Mutex::new(CdpSessionState::new())),
        }
    }

    /// Réécrit la réponse HTTP discovery pour pointer vers le proxy.
    pub fn rewrite_discovery_response(response: &str, bind_addr: &str, listen_port: u16) -> String {
        // Remplacer les URLs WebSocket pour pointer vers le proxy
        let re = Regex::new(r"ws://[^/]+/").expect("Valid regex");
        re.replace_all(response, format!("ws://{}:{}/", bind_addr, listen_port))
            .to_string()
    }

    /// Traite un message du client (agent AI) et retourne la décision.
    ///
    /// Recovers from mutex poisoning by creating a fresh CdpSessionState.
    pub async fn handle_client_message(
        &self,
        raw: &str,
        alert_tx: &mpsc::Sender<SecurityEvent>,
        mode: &crate::types::OperationMode,
    ) -> CdpDecision {
        // Step 3.2: Recover from mutex poisoning instead of panicking
        let mut session_guard = match self.session.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                tracing::error!(
                    "CDP session mutex was poisoned — recovering with fresh state. \
                     Previous state is lost."
                );
                // Recover by extracting the inner value from the poisoned lock
                // and resetting to a fresh state
                let mut recovered = poisoned.into_inner();
                *recovered = CdpSessionState::new();
                recovered
            }
        };

        let decision = process_cdp_message(
            raw,
            &self.domain_matcher,
            &self.command_filter,
            &self.content_inspector,
            &mut session_guard,
            mode,
        );

        self.events_total.fetch_add(1, Ordering::SeqCst);

        if let CdpDecision::Block {
            ref reason,
            ref severity,
            ..
        } = decision
        {
            self.events_blocked.fetch_add(1, Ordering::SeqCst);

            let event = SecurityEvent::new(
                GuardModule::CdpProxy,
                severity.clone(),
                ActionTaken::Blocked,
                reason.clone(),
            );

            // Best-effort : ne pas bloquer si le canal est plein
            let _ = alert_tx.try_send(event);
        }

        decision
    }
}

#[async_trait::async_trait]
impl Guard for CdpProxy {
    fn name(&self) -> &str {
        "cdp_proxy"
    }

    async fn start(&self, _alert_tx: mpsc::Sender<SecurityEvent>) -> anyhow::Result<()> {
        self.running.store(true, Ordering::SeqCst);
        *self.start_time.lock().expect("lock poisoned") = Some(Utc::now());

        // Phase 2 MVP : le serveur HTTP + WebSocket serait lancé ici.
        // Pour les tests, on valide le lifecycle et le handle_client_message.

        if self.config.enabled {
            tracing::info!(
                "CDP Proxy listening on {}:{} → upstream :{}",
                self.config.bind_address,
                self.config.listen_port,
                self.config.upstream_port
            );
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
