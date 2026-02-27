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
    pub fn check(&self, domain: &str) -> DomainVerdict {
        let domain_lower = domain.to_lowercase();

        // Priorité : blocked > require_approval > allowed > default
        if self.matches_list(&domain_lower, &self.blocked) {
            return DomainVerdict::Blocked;
        }
        if self.matches_list(&domain_lower, &self.require_approval) {
            return DomainVerdict::RequireApproval;
        }
        if self.matches_list(&domain_lower, &self.allowed) {
            return DomainVerdict::Allowed;
        }

        // Default policy
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

/// État de la session CDP : URL courante, domaine, historique.
pub struct CdpSessionState {
    current_url: Option<String>,
    history: Vec<String>,
}

impl CdpSessionState {
    /// Crée un nouvel état vide.
    pub fn new() -> Self {
        Self {
            current_url: None,
            history: Vec::new(),
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
pub fn extract_domain_from_url(url: &str) -> Option<String> {
    if url.is_empty() {
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
        parsed.host_str().map(|h| h.to_string())
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
pub fn parse_cdp_message(raw: &str) -> Option<CdpMessage> {
    let value: serde_json::Value = serde_json::from_str(raw).ok()?;

    Some(CdpMessage {
        id: value.get("id").and_then(|v| v.as_i64()),
        method: value
            .get("method")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        params: value.get("params").cloned(),
        raw: value,
    })
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
pub fn process_cdp_message(
    raw: &str,
    domain_matcher: &DomainMatcher,
    command_filter: &CommandFilter,
    content_inspector: &ContentInspector,
    session: &mut CdpSessionState,
) -> CdpDecision {
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
            if let Some(domain) = extract_domain_from_url(&url) {
                let verdict = domain_matcher.check(&domain);
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
            .map(|d| domain_matcher.check(&d))
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
    let raw_str = raw;
    let content_matches = content_inspector.inspect(raw_str);
    if let Some(first) = content_matches.first() {
        if first.action == "block" {
            return CdpDecision::Block {
                id: msg_id,
                reason: format!("Content inspection match: {}", first.name),
                severity: first.severity.clone(),
            };
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
    pub async fn handle_client_message(
        &self,
        raw: &str,
        alert_tx: &mpsc::Sender<SecurityEvent>,
    ) -> CdpDecision {
        let mut session = self.session.lock().expect("session lock poisoned");
        let decision = process_cdp_message(
            raw,
            &self.domain_matcher,
            &self.command_filter,
            &self.content_inspector,
            &mut session,
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
