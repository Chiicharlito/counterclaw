//! Tests TDD pour le Network Egress Guard (Phase 3).
//!
//! Suit la méthodologie Security-First TDD :
//! - Positifs : les destinations autorisées passent
//! - Négatifs : les destinations inconnues sont détectées
//! - Edge cases : entrées étranges gérées proprement
//! - Parsing lsof : extraction correcte des connexions

mod common;

use counterclaw::config::NetGuardConfig;
use counterclaw::guards::net_guard::{ConnectionParser, EgressMatcher, EgressVerdict, NetGuard};
use counterclaw::types::Guard;

// ---------------------------------------------------------------------------
// Helper : config builder
// ---------------------------------------------------------------------------

fn config_with_standard_allowed() -> NetGuardConfig {
    NetGuardConfig {
        enabled: true,
        watch_processes: vec!["openclaw".to_string()],
        allowed_egress: vec![
            "api.anthropic.com".to_string(),
            "github.com".to_string(),
            "api.github.com".to_string(),
            "registry.npmjs.org".to_string(),
            "crates.io".to_string(),
        ],
        max_post_payload_bytes: 51200,
        block_unknown_post: true,
        alert_on_unknown_dns: true,
        enforcement_method: "log_only".to_string(),
    }
}

fn config_empty_allowed() -> NetGuardConfig {
    NetGuardConfig {
        enabled: true,
        watch_processes: vec![],
        allowed_egress: vec![],
        max_post_payload_bytes: 51200,
        block_unknown_post: false,
        alert_on_unknown_dns: false,
        enforcement_method: "log_only".to_string(),
    }
}

// ===========================================================================
// 1. EgressMatcher — Construction
// ===========================================================================

#[test]
fn creates_egress_matcher_from_allowed_list() {
    let config = config_with_standard_allowed();
    let _matcher = EgressMatcher::new(&config.allowed_egress);
    // Pas de panic = succès
}

// ===========================================================================
// 2. EgressMatcher — Domain matching positifs
// ===========================================================================

#[test]
fn allows_anthropic_api() {
    let config = config_with_standard_allowed();
    let matcher = EgressMatcher::new(&config.allowed_egress);
    assert_eq!(matcher.check("api.anthropic.com"), EgressVerdict::Allowed);
}

#[test]
fn allows_github() {
    let config = config_with_standard_allowed();
    let matcher = EgressMatcher::new(&config.allowed_egress);
    assert_eq!(matcher.check("github.com"), EgressVerdict::Allowed);
}

#[test]
fn allows_npm_registry() {
    let config = config_with_standard_allowed();
    let matcher = EgressMatcher::new(&config.allowed_egress);
    assert_eq!(matcher.check("registry.npmjs.org"), EgressVerdict::Allowed);
}

// ===========================================================================
// 3. EgressMatcher — Domain matching négatifs (détection menaces)
// ===========================================================================

#[test]
fn blocks_unknown_domain() {
    let config = config_with_standard_allowed();
    let matcher = EgressMatcher::new(&config.allowed_egress);
    assert_eq!(matcher.check("evil-exfil.com"), EgressVerdict::Blocked);
}

#[test]
fn blocks_random_ip() {
    let config = config_with_standard_allowed();
    let matcher = EgressMatcher::new(&config.allowed_egress);
    assert_eq!(matcher.check("185.234.12.1"), EgressVerdict::Blocked);
}

// ===========================================================================
// 4. EgressMatcher — Edge cases et sécurité
// ===========================================================================

#[test]
fn case_insensitive_matching() {
    let config = config_with_standard_allowed();
    let matcher = EgressMatcher::new(&config.allowed_egress);
    assert_eq!(matcher.check("API.Anthropic.COM"), EgressVerdict::Allowed);
    assert_eq!(matcher.check("GitHub.COM"), EgressVerdict::Allowed);
}

#[test]
fn handles_empty_domain() {
    let config = config_with_standard_allowed();
    let matcher = EgressMatcher::new(&config.allowed_egress);
    assert_eq!(matcher.check(""), EgressVerdict::Blocked);
}

#[test]
fn handles_empty_allowed_list() {
    let config = config_empty_allowed();
    let matcher = EgressMatcher::new(&config.allowed_egress);
    // Tout est bloqué quand la liste est vide
    assert_eq!(matcher.check("github.com"), EgressVerdict::Blocked);
    assert_eq!(matcher.check("any.domain"), EgressVerdict::Blocked);
}

#[test]
fn subdomain_not_auto_allowed() {
    let config = config_with_standard_allowed();
    let matcher = EgressMatcher::new(&config.allowed_egress);
    // "api.anthropic.com" est autorisé, mais "evil.api.anthropic.com" ne l'est PAS
    assert_eq!(
        matcher.check("evil.api.anthropic.com"),
        EgressVerdict::Blocked
    );
}

#[test]
fn blocks_domain_with_trailing_dot() {
    let config = config_with_standard_allowed();
    let matcher = EgressMatcher::new(&config.allowed_egress);
    // "api.anthropic.com." (trailing dot DNS) doit quand même être reconnu
    assert_eq!(matcher.check("api.anthropic.com."), EgressVerdict::Allowed);
}

// ===========================================================================
// 5. ConnectionParser — Parsing lsof
// ===========================================================================

#[test]
fn parses_established_tcp_connection() {
    let output = "COMMAND    PID   USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME\n\
                  node    12345 testuser   15u  IPv4 0x1234567890      0t0  TCP 192.168.1.100:54321->93.184.216.34:443 (ESTABLISHED)";

    let connections = ConnectionParser::parse_lsof_output(output);
    assert_eq!(connections.len(), 1);
    assert_eq!(connections[0].pid, 12345);
    assert_eq!(connections[0].process_name, "node");
    assert_eq!(connections[0].target_ip, "93.184.216.34");
    assert_eq!(connections[0].target_port, 443);
    assert_eq!(connections[0].protocol, "TCP");
}

#[test]
fn parses_multiple_connections() {
    let output = "COMMAND    PID   USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME\n\
                  node    12345 testuser   15u  IPv4 0x1234567890      0t0  TCP 192.168.1.100:54321->93.184.216.34:443 (ESTABLISHED)\n\
                  node    12345 testuser   16u  IPv4 0x1234567891      0t0  TCP 192.168.1.100:54322->185.199.108.153:443 (ESTABLISHED)";

    let connections = ConnectionParser::parse_lsof_output(output);
    assert_eq!(connections.len(), 2);
    assert_eq!(connections[0].target_ip, "93.184.216.34");
    assert_eq!(connections[1].target_ip, "185.199.108.153");
}

#[test]
fn ignores_listen_state() {
    let output = "COMMAND    PID   USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME\n\
                  node    12345 testuser   15u  IPv4 0x1234567890      0t0  TCP *:3000 (LISTEN)";

    let connections = ConnectionParser::parse_lsof_output(output);
    assert!(connections.is_empty());
}

#[test]
fn ignores_header_line() {
    let output = "COMMAND    PID   USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME";
    let connections = ConnectionParser::parse_lsof_output(output);
    assert!(connections.is_empty());
}

#[test]
fn handles_empty_output() {
    let connections = ConnectionParser::parse_lsof_output("");
    assert!(connections.is_empty());
}

#[test]
fn handles_malformed_line() {
    let output = "this is not a valid lsof line\n\
                  another invalid line\n\
                  COMMAND    PID   USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME\n\
                  node    12345 testuser   15u  IPv4 0x1234567890      0t0  TCP 192.168.1.100:54321->93.184.216.34:443 (ESTABLISHED)";

    let connections = ConnectionParser::parse_lsof_output(output);
    // Seule la ligne valide est parsée
    assert_eq!(connections.len(), 1);
}

#[test]
fn extracts_pid_and_process_name() {
    let output = "COMMAND    PID   USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME\n\
                  openclaw  99999 testuser   15u  IPv4 0x1234567890      0t0  TCP 10.0.0.1:8080->1.2.3.4:9090 (ESTABLISHED)";

    let connections = ConnectionParser::parse_lsof_output(output);
    assert_eq!(connections.len(), 1);
    assert_eq!(connections[0].pid, 99999);
    assert_eq!(connections[0].process_name, "openclaw");
}

// ===========================================================================
// 6. NetGuard — Guard lifecycle
// ===========================================================================

#[tokio::test]
async fn guard_starts_and_stops() {
    let config = config_empty_allowed();
    let guard = NetGuard::new(&config);

    let (tx, _rx) = tokio::sync::mpsc::channel(10);

    assert!(!guard.status().running);

    guard.start(tx).await.unwrap();
    assert!(guard.status().running);

    guard.stop().await.unwrap();
    assert!(!guard.status().running);
}

#[test]
fn guard_reports_correct_name() {
    let config = config_empty_allowed();
    let guard = NetGuard::new(&config);
    assert_eq!(guard.name(), "net_guard");
}

#[test]
fn guard_status_initial_values() {
    let config = config_empty_allowed();
    let guard = NetGuard::new(&config);
    let status = guard.status();
    assert!(!status.running);
    assert_eq!(status.events_total, 0);
    assert_eq!(status.events_blocked, 0);
}
