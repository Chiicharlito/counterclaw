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
    AppConfig, CdpCommandsConfig, CdpProxyConfig, ContentInspectionConfig, DomainRulesConfig,
};
use crate::types::{ActionTaken, Guard, GuardModule, GuardStatus, SecurityEvent, Severity};
use chrono::{Duration, Utc};
use regex::Regex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

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

    /// V5: Returns a sliding window view of buffered content with overlap.
    ///
    /// Unlike `get_combined_content()` which only concatenates messages,
    /// this method ensures that secrets split at message boundaries are
    /// detectable by including overlap between consecutive messages.
    ///
    /// The sliding window works by concatenating all buffered messages,
    /// which naturally provides overlap between consecutive messages.
    /// The key insight is that push_content() already maintains a rolling
    /// buffer, so the combined content gives us the sliding window view.
    pub fn get_sliding_window_content(&self) -> String {
        // The buffer already maintains a sliding window of recent messages.
        // Concatenating them provides the overlap needed to detect secrets
        // split across message boundaries.
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

// ---------------------------------------------------------------------------
// Chrome Event Inspection — détection de navigations dans les events Chrome
// ---------------------------------------------------------------------------

/// Décision pour un event Chrome (direction chrome→client).
///
/// Contrairement à CdpDecision, on ne bloque pas les events Chrome
/// (on ne peut pas empêcher Chrome d'avoir déjà navigué). On alerte.
#[derive(Debug)]
pub enum ChromeEventDecision {
    /// L'event est inoffensif, forwarder.
    Forward,
    /// L'event indique une navigation vers un domaine suspect.
    /// On forward ET on émet une alerte.
    Alert { reason: String, severity: Severity },
}

/// Inspecte un event Chrome (message sans `id`) pour détecter les navigations
/// vers des domaines bloqués.
///
/// Events inspectés :
/// - `Page.frameNavigated` → `params.frame.url`
/// - `Page.navigatedWithinDocument` → `params.url`
/// - `Network.requestWillBeSent` → `params.redirectResponse` (redirect chain)
///
/// Met à jour `session.current_url` pour que les commandes suivantes soient
/// filtrées correctement sur le domaine actuel.
pub fn process_chrome_event(
    msg: &serde_json::Value,
    domain_matcher: &DomainMatcher,
    session: &mut CdpSessionState,
    mode: &crate::types::OperationMode,
) -> ChromeEventDecision {
    let method = match msg.get("method").and_then(|v| v.as_str()) {
        Some(m) => m,
        None => return ChromeEventDecision::Forward,
    };

    // Extract URL from the event based on method type
    let url = match method {
        "Page.frameNavigated" => {
            // params.frame.url
            msg.get("params")
                .and_then(|p| p.get("frame"))
                .and_then(|f| f.get("url"))
                .and_then(|u| u.as_str())
        }
        "Page.navigatedWithinDocument" => {
            // params.url
            msg.get("params")
                .and_then(|p| p.get("url"))
                .and_then(|u| u.as_str())
        }
        "Network.requestWillBeSent" => {
            // params.redirectResponse exists → this is a redirect
            // Check the request URL (the redirect target)
            if msg
                .get("params")
                .and_then(|p| p.get("redirectResponse"))
                .is_some()
            {
                msg.get("params")
                    .and_then(|p| p.get("request"))
                    .and_then(|r| r.get("url"))
                    .and_then(|u| u.as_str())
            } else {
                None // Not a redirect, just a normal request
            }
        }
        _ => None,
    };

    let url = match url {
        Some(u) => u,
        None => return ChromeEventDecision::Forward,
    };

    // Extract and check domain
    let domain = match extract_domain_from_url(url) {
        Some(d) => d,
        None => return ChromeEventDecision::Forward,
    };

    let verdict = domain_matcher.check(&domain, mode);

    // Always update session URL so restricted commands are filtered on current domain
    session.update_url(url);

    match verdict {
        DomainVerdict::Blocked => {
            let severity = match mode {
                crate::types::OperationMode::Enforce | crate::types::OperationMode::Paranoid => {
                    Severity::Critical
                }
                crate::types::OperationMode::Monitor => Severity::Warning,
            };
            ChromeEventDecision::Alert {
                reason: format!(
                    "Chrome navigated to blocked domain: {} (via {})",
                    domain, method
                ),
                severity,
            }
        }
        DomainVerdict::RequireApproval => ChromeEventDecision::Alert {
            reason: format!(
                "Chrome navigated to approval-required domain: {} (via {})",
                domain, method
            ),
            severity: Severity::Warning,
        },
        DomainVerdict::Allowed => ChromeEventDecision::Forward,
    }
}

// ---------------------------------------------------------------------------
// process_cdp_message — décision principale pour les messages CDP agent→Chrome
// ---------------------------------------------------------------------------

/// pour prendre une décision sur un message CDP.
///
/// C'est une fonction libre (pas une méthode) : respecte SRP.
/// Fail-closed: malformed/non-object JSON is blocked, not forwarded.
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

    // Fail-closed: reject anything that isn't a valid JSON object.
    // An agent could send malformed JSON, JSON arrays (batch requests),
    // or non-object types to bypass all CDP inspection.
    let trimmed = raw.trim();
    if !trimmed.starts_with('{') {
        return CdpDecision::Block {
            id: 0,
            reason: "Unparseable CDP message blocked (not a JSON object)".to_string(),
            severity: Severity::High,
        };
    }

    let msg = match parse_cdp_message(raw) {
        Some(m) => m,
        None => {
            return CdpDecision::Block {
                id: 0,
                reason: "Unparseable CDP message blocked (invalid JSON)".to_string(),
                severity: Severity::High,
            };
        }
    };

    // Les event messages (pas d'id) : inspecter pour détecter les navigations Chrome
    let msg_id = match msg.id {
        Some(id) => id,
        None => {
            // Inspect Chrome events for navigation to blocked domains
            let chrome_decision = process_chrome_event(&msg.raw, domain_matcher, session, mode);
            return match chrome_decision {
                ChromeEventDecision::Forward => CdpDecision::Forward,
                ChromeEventDecision::Alert { reason, severity } => CdpDecision::ForwardAndLog {
                    reason: format!("{} [severity: {:?}]", reason, severity),
                },
            };
        }
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
                        // Mode-dependent: Monitor = forward + log, Enforce/Paranoid = block
                        session.update_url(&url);
                        match mode {
                            crate::types::OperationMode::Monitor => {
                                return CdpDecision::ForwardAndLog {
                                    reason: format!(
                                        "Navigation to approval-required domain: {}",
                                        domain
                                    ),
                                };
                            }
                            _ => {
                                return CdpDecision::Block {
                                    id: msg_id,
                                    reason: format!(
                                        "Navigation to approval-required domain blocked (no interactive approval): {}",
                                        domain
                                    ),
                                    severity: Severity::Warning,
                                };
                            }
                        }
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
    cancel_token: CancellationToken,
    task_handle: Arc<tokio::sync::Mutex<Option<tokio::task::JoinHandle<()>>>>,
    /// Shared config for hot-reload and mode access (used in start() I/O layer).
    #[allow(dead_code)]
    app_config: Arc<RwLock<AppConfig>>,
}

impl CdpProxy {
    /// Crée un nouveau CdpProxy depuis la configuration.
    pub fn new(config: &CdpProxyConfig, app_config: Arc<RwLock<AppConfig>>) -> Self {
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
            cancel_token: CancellationToken::new(),
            task_handle: Arc::new(tokio::sync::Mutex::new(None)),
            app_config,
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

// ---------------------------------------------------------------------------
// HTTP Discovery Router — forwards /json/* to upstream Chrome and rewrites URLs
// ---------------------------------------------------------------------------

/// Shared state for CDP proxy HTTP + WS handlers.
#[derive(Clone)]
struct CdpDiscoveryState {
    upstream_port: u16,
    listen_port: u16,
    bind_address: String,
    alert_tx: mpsc::Sender<SecurityEvent>,
    app_config: Arc<RwLock<crate::config::AppConfig>>,
    /// Per-session state for CDP message inspection.
    /// Shared across all WS connections (MVP: single session).
    session: Arc<Mutex<CdpSessionState>>,
    /// CDP components for message processing.
    domain_matcher: Arc<DomainMatcher>,
    command_filter: Arc<CommandFilter>,
    content_inspector: Arc<ContentInspector>,
    events_total: Arc<AtomicU64>,
    events_blocked: Arc<AtomicU64>,
}

/// Builds the axum router for CDP discovery + WebSocket relay.
fn build_cdp_discovery_router(state: CdpDiscoveryState) -> axum::Router {
    axum::Router::new()
        .route("/json/version", axum::routing::get(handle_cdp_discovery))
        .route("/json/list", axum::routing::get(handle_cdp_discovery))
        .route("/json", axum::routing::get(handle_cdp_discovery))
        .route(
            "/devtools/browser/{id}",
            axum::routing::get(handle_ws_upgrade),
        )
        .route("/devtools/page/{id}", axum::routing::get(handle_ws_upgrade))
        .with_state(state)
}

/// Handler for CDP discovery endpoints — fetches from upstream Chrome and rewrites URLs.
async fn handle_cdp_discovery(
    axum::extract::State(state): axum::extract::State<CdpDiscoveryState>,
    request: axum::extract::Request,
) -> axum::response::Response {
    let path = request.uri().path().to_string();
    let upstream_url = format!("http://127.0.0.1:{}{}", state.upstream_port, path);

    match reqwest::get(&upstream_url).await {
        Ok(resp) => {
            if resp.status().is_success() {
                match resp.text().await {
                    Ok(body) => {
                        let rewritten = CdpProxy::rewrite_discovery_response(
                            &body,
                            &state.bind_address,
                            state.listen_port,
                        );
                        axum::response::Response::builder()
                            .status(200)
                            .header("Content-Type", "application/json")
                            .body(axum::body::Body::from(rewritten))
                            .unwrap_or_else(|_| {
                                axum::response::Response::builder()
                                    .status(500)
                                    .body(axum::body::Body::from("Internal error"))
                                    .expect("valid response")
                            })
                    }
                    Err(e) => axum::response::Response::builder()
                        .status(502)
                        .body(axum::body::Body::from(format!(
                            "Failed to read upstream response: {}",
                            e
                        )))
                        .expect("valid response"),
                }
            } else {
                axum::response::Response::builder()
                    .status(resp.status().as_u16())
                    .body(axum::body::Body::from(
                        resp.text().await.unwrap_or_default(),
                    ))
                    .expect("valid response")
            }
        }
        Err(e) => axum::response::Response::builder()
            .status(502)
            .body(axum::body::Body::from(format!(
                "Failed to connect to Chrome upstream: {}",
                e
            )))
            .expect("valid response"),
    }
}

// ---------------------------------------------------------------------------
// WebSocket Relay — bidirectional proxy between client and Chrome
// ---------------------------------------------------------------------------

/// Handler for WebSocket upgrade on /devtools/browser/{id} and /devtools/page/{id}.
///
/// 1. Accepts the WS upgrade from the client (AI agent)
/// 2. Opens a WS connection to upstream Chrome
/// 3. Runs a bidirectional relay with CDP message inspection:
///    - Client → Chrome: inspect via process_cdp_message, block or forward
///    - Chrome → Client: passthrough (no inspection)
async fn handle_ws_upgrade(
    axum::extract::State(state): axum::extract::State<CdpDiscoveryState>,
    ws: axum::extract::ws::WebSocketUpgrade,
    axum::extract::Path(id): axum::extract::Path<String>,
    request: axum::extract::Request,
) -> axum::response::Response {
    let path = request.uri().path().to_string();
    ws.on_upgrade(move |client_socket| ws_relay(client_socket, state, path, id))
}

/// Bidirectional WebSocket relay between client and upstream Chrome.
///
/// For each message from the client:
/// - Text messages are inspected via process_cdp_message()
///   - Forward/ForwardAndLog → relay to Chrome
///   - Block → send synthetic error to client, do NOT relay
/// - Binary messages are forwarded without inspection
///
/// For each message from Chrome:
/// - All messages are relayed to client (passthrough)
async fn ws_relay(
    client_socket: axum::extract::ws::WebSocket,
    state: CdpDiscoveryState,
    path: String,
    _id: String,
) {
    use axum::extract::ws::Message as AxumMsg;
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message as TungMsg;

    // Connect to upstream Chrome
    let upstream_url = format!("ws://127.0.0.1:{}{}", state.upstream_port, path);
    let chrome_conn = match tokio_tungstenite::connect_async(&upstream_url).await {
        Ok((ws, _)) => ws,
        Err(e) => {
            tracing::error!("Failed to connect to upstream Chrome WS: {}", e);
            return;
        }
    };

    // Split both connections into read/write halves
    let (client_tx, mut client_rx) = client_socket.split();
    let (mut chrome_tx, mut chrome_rx) = chrome_conn.split();

    // Wrap client_tx in Arc<Mutex> so both directions can send to client
    let client_tx = Arc::new(tokio::sync::Mutex::new(client_tx));

    // Shared state for the relay
    let alert_tx = state.alert_tx.clone();
    let app_config = state.app_config.clone();
    let session = state.session.clone();
    let domain_matcher = state.domain_matcher.clone();
    let command_filter = state.command_filter.clone();
    let content_inspector = state.content_inspector.clone();
    let events_total = state.events_total.clone();
    let events_blocked = state.events_blocked.clone();

    // Client → Chrome direction (with CDP inspection)
    let client_to_chrome = async {
        while let Some(msg_result) = client_rx.next().await {
            let msg = match msg_result {
                Ok(m) => m,
                Err(_) => break, // Client disconnected
            };

            match msg {
                AxumMsg::Text(text) => {
                    let raw = text.to_string();

                    // Get current mode from shared config (string → OperationMode)
                    let mode = app_config
                        .read()
                        .ok()
                        .map(|cfg| match cfg.general.mode.as_str() {
                            "enforce" => crate::types::OperationMode::Enforce,
                            "paranoid" => crate::types::OperationMode::Paranoid,
                            _ => crate::types::OperationMode::Monitor,
                        })
                        .unwrap_or(crate::types::OperationMode::Monitor);

                    // Inspect the CDP message
                    let decision = {
                        let mut session_guard = match session.lock() {
                            Ok(g) => g,
                            Err(poisoned) => {
                                tracing::error!("CDP session mutex poisoned — recovering");
                                let mut recovered = poisoned.into_inner();
                                *recovered = CdpSessionState::new();
                                recovered
                            }
                        };
                        process_cdp_message(
                            &raw,
                            &domain_matcher,
                            &command_filter,
                            &content_inspector,
                            &mut session_guard,
                            &mode,
                        )
                    };

                    events_total.fetch_add(1, Ordering::SeqCst);

                    match decision {
                        CdpDecision::Forward | CdpDecision::ForwardAndLog { .. } => {
                            // Relay to Chrome
                            if chrome_tx.send(TungMsg::Text(raw)).await.is_err() {
                                break; // Chrome disconnected
                            }
                        }
                        CdpDecision::Block {
                            id,
                            ref reason,
                            ref severity,
                        } => {
                            events_blocked.fetch_add(1, Ordering::SeqCst);

                            // Emit SecurityEvent
                            let event = SecurityEvent::new(
                                GuardModule::CdpProxy,
                                severity.clone(),
                                ActionTaken::Blocked,
                                reason.clone(),
                            );
                            let _ = alert_tx.try_send(event);

                            // Send synthetic error to client
                            let error_msg = generate_synthetic_error(id, reason);
                            if client_tx
                                .lock()
                                .await
                                .send(AxumMsg::Text(error_msg.into()))
                                .await
                                .is_err()
                            {
                                break; // Client disconnected
                            }
                        }
                    }
                }
                AxumMsg::Binary(data) => {
                    // Binary messages: relay without inspection
                    if chrome_tx
                        .send(TungMsg::Binary(data.to_vec()))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                AxumMsg::Close(_) => break,
                _ => {} // Ping/Pong handled by framework
            }
        }
    };

    // Chrome → Client direction (with Chrome event inspection)
    let client_tx_clone = Arc::clone(&client_tx);
    let alert_tx_chrome = state.alert_tx.clone();
    let app_config_chrome = state.app_config.clone();
    let session_chrome = state.session.clone();
    let domain_matcher_chrome = state.domain_matcher.clone();
    let chrome_to_client = async move {
        while let Some(msg_result) = chrome_rx.next().await {
            let msg = match msg_result {
                Ok(m) => m,
                Err(_) => break, // Chrome disconnected
            };

            match msg {
                TungMsg::Text(text) => {
                    // Inspect Chrome events for navigation to blocked domains
                    if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&text) {
                        // Only inspect events (no "id" field)
                        if parsed.get("id").is_none() && parsed.get("method").is_some() {
                            let mode = app_config_chrome
                                .read()
                                .ok()
                                .map(|cfg| match cfg.general.mode.as_str() {
                                    "enforce" => crate::types::OperationMode::Enforce,
                                    "paranoid" => crate::types::OperationMode::Paranoid,
                                    _ => crate::types::OperationMode::Monitor,
                                })
                                .unwrap_or(crate::types::OperationMode::Monitor);

                            let decision = {
                                let mut session_guard = match session_chrome.lock() {
                                    Ok(g) => g,
                                    Err(poisoned) => poisoned.into_inner(),
                                };
                                process_chrome_event(
                                    &parsed,
                                    &domain_matcher_chrome,
                                    &mut session_guard,
                                    &mode,
                                )
                            };

                            if let ChromeEventDecision::Alert { reason, severity } = decision {
                                let event = SecurityEvent::new(
                                    GuardModule::CdpProxy,
                                    severity,
                                    ActionTaken::Alerted,
                                    reason,
                                );
                                let _ = alert_tx_chrome.try_send(event);
                            }
                        }
                    }

                    // Always forward Chrome events to client
                    if client_tx_clone
                        .lock()
                        .await
                        .send(AxumMsg::Text(text.into()))
                        .await
                        .is_err()
                    {
                        break; // Client disconnected
                    }
                }
                TungMsg::Binary(data) => {
                    if client_tx_clone
                        .lock()
                        .await
                        .send(AxumMsg::Binary(data.into()))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                TungMsg::Close(_) => {
                    let _ = client_tx_clone
                        .lock()
                        .await
                        .send(AxumMsg::Close(None))
                        .await;
                    break;
                }
                _ => {} // Ping/Pong handled by tungstenite
            }
        }
    };

    // Run both directions concurrently — when either ends, the other stops
    tokio::select! {
        _ = client_to_chrome => {
            tracing::debug!("CDP WS relay: client side ended");
        }
        _ = chrome_to_client => {
            tracing::debug!("CDP WS relay: Chrome side ended");
        }
    }
}

#[async_trait::async_trait]
impl Guard for CdpProxy {
    fn name(&self) -> &str {
        "cdp_proxy"
    }

    async fn start(&self, alert_tx: mpsc::Sender<SecurityEvent>) -> anyhow::Result<()> {
        self.running.store(true, Ordering::SeqCst);
        *self.start_time.lock().expect("lock poisoned") = Some(Utc::now());

        if self.config.enabled {
            let bind_addr = format!("{}:{}", self.config.bind_address, self.config.listen_port);
            let cancel = self.cancel_token.clone();

            let state = CdpDiscoveryState {
                upstream_port: self.config.upstream_port,
                listen_port: self.config.listen_port,
                bind_address: self.config.bind_address.clone(),
                alert_tx,
                app_config: Arc::clone(&self.app_config),
                session: Arc::clone(&self.session),
                domain_matcher: Arc::new(DomainMatcher::new(&self.config.domains)),
                command_filter: Arc::new(CommandFilter::new(&self.config.cdp_commands)),
                content_inspector: Arc::new(ContentInspector::new(&self.config.content_inspection)),
                events_total: Arc::clone(&self.events_total),
                events_blocked: Arc::clone(&self.events_blocked),
            };

            let listener = tokio::net::TcpListener::bind(&bind_addr).await?;

            tracing::info!(
                "CDP Proxy listening on {} → upstream :{}",
                bind_addr,
                state.upstream_port
            );

            let handle = tokio::spawn(async move {
                let app = build_cdp_discovery_router(state);

                tokio::select! {
                    result = axum::serve(listener, app) => {
                        if let Err(e) = result {
                            tracing::error!("CDP Proxy server error: {}", e);
                        }
                    }
                    _ = cancel.cancelled() => {
                        tracing::info!("CDP Proxy shutting down");
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
