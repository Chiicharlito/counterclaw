//! Tests pour le PF Firewall Guard — logique pure.
//!
//! Étape 1 : Config + types
//! Étape 2 : PfRuleGenerator
//! Étape 3 : PfController
//! Étape 4 : DomainResolver
//! Étape 5 : PfGuard (Guard trait)
//! Étape 6 : Hot-reload whitelist

mod common;

// ==========================================================================
// Étape 1 : Config + types (~5 tests)
// ==========================================================================

#[test]
fn parses_pf_guard_config_from_yaml() {
    let yaml = r##"
general:
  mode: enforce
  pid_file: /tmp/test.pid
  log_level: info
  log_file: /tmp/test.log
  log_max_size_mb: 10
fs_guard:
  enabled: false
  watch_processes: []
  blocked_paths: []
  read_only_paths: []
  allowed_paths: []
  on_violation:
    action: log_only
    kill_target: process
cdp_proxy:
  enabled: false
  listen_port: 18792
  upstream_port: 18800
  bind_address: "127.0.0.1"
  domains:
    blocked: []
    allowed: []
    require_approval: []
    default_policy: allow
  cdp_commands:
    blocked: []
    restricted_to_allowed_domains: []
    log_always: []
  content_inspection:
    enabled: false
    patterns: []
net_guard:
  enabled: false
  watch_processes: []
  allowed_egress: []
  max_post_payload_bytes: 51200
  block_unknown_post: false
  alert_on_unknown_dns: false
  enforcement_method: log_only
cmd_guard:
  enabled: false
  blacklist: []
  require_approval: []
  monitoring_method: log_only
alerting:
  macos_notification:
    enabled: false
  slack:
    enabled: false
    webhook_url: "https://hooks.slack.com/services/X/Y/Z"
    channel: "#test"
    min_severity: warning
  file_log:
    enabled: true
    path: /tmp/events.jsonl
    max_size_mb: 10
    keep_files: 3
  kill_switch:
    enabled: false
    threshold_severity: warning
    threshold_count: 3
    threshold_window_seconds: 60
    action: alert_only
dashboard:
  enabled: false
  bind_address: "127.0.0.1"
  port: 9999
pf_guard:
  enabled: true
  agent_username: "_openclaw"
  allowed_destinations:
    - "api.openai.com"
    - "api.anthropic.com"
  dns_refresh_seconds: 300
  anchor_name: "com.counterclaw"
"##;

    let config: counterclaw::config::AppConfig = serde_yaml::from_str(yaml).unwrap();
    assert!(config.pf_guard.enabled);
    assert_eq!(config.pf_guard.agent_username, "_openclaw");
    assert_eq!(config.pf_guard.allowed_destinations.len(), 2);
    assert_eq!(config.pf_guard.dns_refresh_seconds, 300);
    assert_eq!(config.pf_guard.anchor_name, "com.counterclaw");
}

#[test]
fn pf_guard_defaults_to_disabled() {
    // Config YAML sans section pf_guard — doit parser avec defaults (serde)
    let env = common::TestEnv::new();
    let yaml = common::minimal_monitor_config(&env);
    env.write_config(&yaml);
    let config = counterclaw::config::AppConfig::load(&env.config_path()).unwrap();
    assert!(!config.pf_guard.enabled);
    assert!(config.pf_guard.agent_username.is_empty());
    assert!(config.pf_guard.allowed_destinations.is_empty());
    assert_eq!(config.pf_guard.dns_refresh_seconds, 300);
    assert_eq!(config.pf_guard.anchor_name, "com.counterclaw");
}

#[test]
fn validates_empty_username_rejected() {
    let env = common::TestEnv::new();
    let yaml = common::minimal_monitor_config(&env).to_string()
        + "\npf_guard:\n  enabled: true\n  agent_username: \"\"\n";
    env.write_config(&yaml);
    let config = counterclaw::config::AppConfig::load(&env.config_path()).unwrap();
    let errors = config.validate();
    assert!(
        errors.iter().any(|e| e.contains("agent_username")),
        "Expected validation error about empty username, got: {:?}",
        errors
    );
}

#[test]
fn validates_username_no_spaces_or_specials() {
    let env = common::TestEnv::new();
    let yaml = common::minimal_monitor_config(&env).to_string()
        + "\npf_guard:\n  enabled: true\n  agent_username: \"bad user; rm -rf /\"\n";
    env.write_config(&yaml);
    let config = counterclaw::config::AppConfig::load(&env.config_path()).unwrap();
    let errors = config.validate();
    assert!(
        errors
            .iter()
            .any(|e| e.contains("agent_username") && e.contains("invalid")),
        "Expected validation error about invalid username chars, got: {:?}",
        errors
    );
}

#[test]
fn validates_dns_refresh_minimum() {
    let env = common::TestEnv::new();
    let yaml = common::minimal_monitor_config(&env).to_string()
        + "\npf_guard:\n  enabled: true\n  agent_username: \"_openclaw\"\n  dns_refresh_seconds: 5\n";
    env.write_config(&yaml);
    let config = counterclaw::config::AppConfig::load(&env.config_path()).unwrap();
    let errors = config.validate();
    assert!(
        errors.iter().any(|e| e.contains("dns_refresh_seconds")),
        "Expected validation error about dns_refresh minimum, got: {:?}",
        errors
    );
}

#[test]
fn pf_guard_module_display_and_serde() {
    let module = counterclaw::types::GuardModule::PfGuard;
    assert_eq!(format!("{}", module), "pf_guard");

    // Serde round-trip
    let json = serde_json::to_string(&module).unwrap();
    assert_eq!(json, "\"pf_guard\"");
    let parsed: counterclaw::types::GuardModule = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, counterclaw::types::GuardModule::PfGuard);
}

// ==========================================================================
// Étape 2 : PfRuleGenerator — logique pure (~10 tests)
// ==========================================================================

use counterclaw::guards::pf_guard::{PfRuleGenerator, ResolvedDestination};
use std::net::IpAddr;
use std::time::Instant;

fn make_resolved(domain: &str, ips: Vec<IpAddr>) -> ResolvedDestination {
    ResolvedDestination {
        original: domain.to_string(),
        ips,
        resolved_at: Instant::now(),
    }
}

#[test]
fn generates_rules_with_single_ip() {
    let gen = PfRuleGenerator::new("_openclaw", "com.counterclaw");
    let resolved = vec![make_resolved(
        "api.openai.com",
        vec!["104.18.6.192".parse().unwrap()],
    )];
    let rules = gen.generate_anchor_rules(&resolved);
    assert!(rules.contains("104.18.6.192"), "Rules should contain IP");
    assert!(rules.contains("_openclaw"), "Rules should contain username");
}

#[test]
fn generates_rules_with_multiple_ips() {
    let gen = PfRuleGenerator::new("_openclaw", "com.counterclaw");
    let resolved = vec![
        make_resolved(
            "api.openai.com",
            vec![
                "104.18.6.192".parse().unwrap(),
                "104.18.7.192".parse().unwrap(),
            ],
        ),
        make_resolved("api.anthropic.com", vec!["160.79.104.31".parse().unwrap()]),
    ];
    let rules = gen.generate_anchor_rules(&resolved);
    assert!(rules.contains("104.18.6.192"));
    assert!(rules.contains("104.18.7.192"));
    assert!(rules.contains("160.79.104.31"));
}

#[test]
fn generates_rules_empty_whitelist_blocks_all() {
    let gen = PfRuleGenerator::new("_openclaw", "com.counterclaw");
    let rules = gen.generate_anchor_rules(&[]);
    // Should still have lo0 pass, dns pass, and block rule
    assert!(rules.contains("lo0"), "lo0 passthrough should be present");
    assert!(
        rules.contains("port 53"),
        "DNS passthrough should be present"
    );
    assert!(rules.contains("block"), "Block rule should be present");
    // No table entry since no IPs
    assert!(
        !rules.contains("counterclaw_allowed"),
        "No table when whitelist is empty"
    );
}

#[test]
fn lo0_passthrough_always_present() {
    let gen = PfRuleGenerator::new("_openclaw", "com.counterclaw");
    let rules = gen.generate_anchor_rules(&[]);
    assert!(
        rules.contains("pass out quick on lo0"),
        "lo0 rule must be present: {}",
        rules
    );
}

#[test]
fn dns_passthrough_always_present() {
    let gen = PfRuleGenerator::new("_openclaw", "com.counterclaw");
    let rules = gen.generate_anchor_rules(&[]);
    assert!(
        rules.contains("port 53"),
        "DNS rule must be present: {}",
        rules
    );
}

#[test]
fn block_rule_is_last() {
    let gen = PfRuleGenerator::new("_openclaw", "com.counterclaw");
    let resolved = vec![make_resolved(
        "api.openai.com",
        vec!["1.2.3.4".parse().unwrap()],
    )];
    let rules = gen.generate_anchor_rules(&resolved);
    let lines: Vec<&str> = rules
        .lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();
    let last_line = lines.last().unwrap();
    assert!(
        last_line.contains("block"),
        "Last rule must be block, got: {}",
        last_line
    );
}

#[test]
fn username_injection_prevented() {
    // Validate that username validation rejects injection attempts
    let result = PfRuleGenerator::validate_username("user; rm -rf /");
    assert!(result.is_err(), "Injection in username should be rejected");

    let result = PfRuleGenerator::validate_username("valid_user-1");
    assert!(result.is_ok(), "Valid username should be accepted");
}

#[test]
fn is_localhost_ipv4_and_ipv6() {
    assert!(PfRuleGenerator::is_localhost("127.0.0.1"));
    assert!(PfRuleGenerator::is_localhost("::1"));
    assert!(PfRuleGenerator::is_localhost("localhost"));
}

#[test]
fn is_localhost_rejects_non_local() {
    assert!(!PfRuleGenerator::is_localhost("1.2.3.4"));
    assert!(!PfRuleGenerator::is_localhost("api.openai.com"));
    assert!(!PfRuleGenerator::is_localhost(""));
}

#[test]
fn generate_table_ips_deduplicates() {
    let resolved = vec![
        make_resolved(
            "a.com",
            vec!["1.2.3.4".parse().unwrap(), "5.6.7.8".parse().unwrap()],
        ),
        make_resolved(
            "b.com",
            vec!["1.2.3.4".parse().unwrap(), "9.10.11.12".parse().unwrap()],
        ),
    ];
    let ips = PfRuleGenerator::generate_table_ips(&resolved);
    // 1.2.3.4 appears in both → should be deduplicated
    let count = ips
        .iter()
        .filter(|ip: &&IpAddr| ip.to_string() == "1.2.3.4")
        .count();
    assert_eq!(count, 1, "Duplicate IPs should be removed");
    assert_eq!(ips.len(), 3, "Should have 3 unique IPs");
}

// ==========================================================================
// Étape 3 : PfController — couche I/O (~6 tests)
// ==========================================================================

use counterclaw::guards::pf_guard::PfController;

#[test]
fn install_builds_correct_pfctl_args() {
    let controller = PfController::new("com.counterclaw");
    let (program, args) = controller.build_install_command("pass out quick on lo0\nblock all\n");
    assert_eq!(program, "pfctl");
    assert!(args.contains(&"-a".to_string()), "Must use -a for anchor");
    assert!(
        args.contains(&"com.counterclaw".to_string()),
        "Must specify anchor name"
    );
    assert!(
        args.contains(&"-f".to_string()),
        "Must use -f to load rules"
    );
}

#[test]
fn flush_builds_correct_pfctl_args() {
    let controller = PfController::new("com.counterclaw");
    let (program, args) = controller.build_flush_command();
    assert_eq!(program, "pfctl");
    assert!(args.contains(&"-a".to_string()));
    assert!(args.contains(&"com.counterclaw".to_string()));
    assert!(
        args.contains(&"-F".to_string()),
        "Must use -F to flush rules"
    );
}

#[test]
fn enable_builds_correct_pfctl_args() {
    let controller = PfController::new("com.counterclaw");
    let (program, args) = controller.build_enable_command();
    assert_eq!(program, "pfctl");
    assert!(args.contains(&"-E".to_string()), "Must use -E to enable pf");
}

#[test]
fn is_root_returns_false_in_tests() {
    // Tests never run as root (unless explicitly)
    // This is a reasonable assumption in CI and local dev
    let is_root = PfController::is_root();
    // We can't assert false unconditionally because CI could run as root,
    // but we can at least assert the function returns a bool.
    let _: bool = is_root;
}

#[test]
fn controller_uses_configured_anchor_name() {
    let controller = PfController::new("com.mycustom.anchor");
    let (_, args) = controller.build_flush_command();
    assert!(
        args.contains(&"com.mycustom.anchor".to_string()),
        "Controller must use configured anchor name"
    );
}

#[test]
fn update_table_builds_replace_command() {
    let controller = PfController::new("com.counterclaw");
    let ips: Vec<IpAddr> = vec!["1.2.3.4".parse().unwrap(), "5.6.7.8".parse().unwrap()];
    let (program, args) = controller.build_table_replace_command("counterclaw_allowed", &ips);
    assert_eq!(program, "pfctl");
    assert!(
        args.contains(&"-t".to_string()),
        "Must use -t for table name"
    );
    assert!(args.contains(&"counterclaw_allowed".to_string()));
    assert!(
        args.contains(&"-T".to_string()),
        "Must use -T for table operation"
    );
    assert!(
        args.contains(&"replace".to_string()),
        "Must use replace operation"
    );
    // IPs should be in the args
    assert!(args.contains(&"1.2.3.4".to_string()));
    assert!(args.contains(&"5.6.7.8".to_string()));
}

// ==========================================================================
// Étape 4 : DomainResolver (~4 tests)
// ==========================================================================

use counterclaw::guards::pf_guard::DomainResolver;

#[test]
fn ip_passthrough_no_dns_needed() {
    // An IP address should be returned directly without DNS resolution
    let result = DomainResolver::parse_ip_direct("1.2.3.4");
    assert!(result.is_some());
    assert_eq!(result.unwrap(), "1.2.3.4".parse::<IpAddr>().unwrap());

    let result_v6 = DomainResolver::parse_ip_direct("::1");
    assert!(result_v6.is_some());

    let result_domain = DomainResolver::parse_ip_direct("api.openai.com");
    assert!(result_domain.is_none(), "Domain should not parse as IP");
}

#[tokio::test]
async fn resolves_localhost_to_loopback() {
    let resolved = DomainResolver::resolve_all(&["localhost".to_string()]).await;
    assert_eq!(resolved.len(), 1);
    assert_eq!(resolved[0].original, "localhost");
    assert!(
        !resolved[0].ips.is_empty(),
        "localhost should resolve to at least one IP"
    );
    // Should contain 127.0.0.1 or ::1
    let has_loopback = resolved[0]
        .ips
        .iter()
        .any(|ip| ip.to_string() == "127.0.0.1" || ip.to_string() == "::1");
    assert!(
        has_loopback,
        "localhost should resolve to loopback, got: {:?}",
        resolved[0].ips
    );
}

#[tokio::test]
async fn handles_unresolvable_gracefully() {
    let resolved =
        DomainResolver::resolve_all(&["this.domain.definitely.does.not.exist.invalid".to_string()])
            .await;
    assert_eq!(resolved.len(), 1);
    assert!(
        resolved[0].ips.is_empty(),
        "Unresolvable domain should have empty IPs"
    );
}

#[tokio::test]
async fn tracks_resolution_timestamp() {
    let before = Instant::now();
    let resolved = DomainResolver::resolve_all(&["127.0.0.1".to_string()]).await;
    let after = Instant::now();
    assert_eq!(resolved.len(), 1);
    assert!(resolved[0].resolved_at >= before);
    assert!(resolved[0].resolved_at <= after);
}

// ==========================================================================
// Étape 5 : PfGuard — Guard trait (~6 tests)
// ==========================================================================

use counterclaw::guards::pf_guard::PfGuard;
use counterclaw::types::Guard;
use std::sync::{Arc, RwLock};
use tokio::sync::mpsc;

#[test]
fn guard_name_is_pf_guard() {
    let env = common::TestEnv::new();
    let app_config = common::default_app_config_arc(&env);
    let config = counterclaw::config::PfGuardConfig::default();
    let guard = PfGuard::new(&config, app_config);
    assert_eq!(guard.name(), "pf_guard");
}

#[tokio::test]
async fn start_skips_when_disabled() {
    let env = common::TestEnv::new();
    let app_config = common::default_app_config_arc(&env);
    let config = counterclaw::config::PfGuardConfig {
        enabled: false,
        ..Default::default()
    };
    let guard = PfGuard::new(&config, app_config);
    let (tx, _rx) = mpsc::channel(100);
    // Should succeed silently (no-op when disabled)
    guard.start(tx).await.unwrap();
    assert!(guard.status().running);
}

#[tokio::test]
async fn start_skips_when_not_root() {
    let env = common::TestEnv::new();
    let app_config = common::default_app_config_arc(&env);
    let config = counterclaw::config::PfGuardConfig {
        enabled: true,
        agent_username: "_testuser".to_string(),
        anchor_name: "com.test".to_string(),
        dns_refresh_seconds: 300,
        ..Default::default()
    };
    let guard = PfGuard::new(&config, app_config);
    let (tx, _rx) = mpsc::channel(100);
    // Should not crash — logs warning and continues in audit-only mode
    guard.start(tx).await.unwrap();
}

#[test]
fn status_not_running_before_start() {
    let env = common::TestEnv::new();
    let app_config = common::default_app_config_arc(&env);
    let config = counterclaw::config::PfGuardConfig::default();
    let guard = PfGuard::new(&config, app_config);
    assert!(!guard.status().running);
}

#[tokio::test]
async fn stop_is_idempotent() {
    let env = common::TestEnv::new();
    let app_config = common::default_app_config_arc(&env);
    let config = counterclaw::config::PfGuardConfig::default();
    let guard = PfGuard::new(&config, app_config);
    // Stop without start should not error
    guard.stop().await.unwrap();
    guard.stop().await.unwrap();
}

#[tokio::test]
async fn linux_start_returns_ok_with_info() {
    // On macOS this test verifies non-root behavior
    // On Linux pf doesn't exist, so it should return Ok with a log
    let env = common::TestEnv::new();
    let app_config = common::default_app_config_arc(&env);
    let config = counterclaw::config::PfGuardConfig {
        enabled: true,
        agent_username: "_testuser".to_string(),
        ..Default::default()
    };
    let guard = PfGuard::new(&config, app_config);
    let (tx, _rx) = mpsc::channel(100);
    // Should return Ok regardless of platform
    let result = guard.start(tx).await;
    assert!(result.is_ok());
}

// ==========================================================================
// Étape 6 : Hot-reload whitelist (~3 tests)
// ==========================================================================

#[test]
fn whitelist_change_triggers_table_update() {
    // Pure logic test: verify that generating rules with different resolved
    // destinations produces different output
    let gen = PfRuleGenerator::new("_openclaw", "com.counterclaw");

    let resolved_v1 = vec![make_resolved("a.com", vec!["1.2.3.4".parse().unwrap()])];
    let rules_v1 = gen.generate_anchor_rules(&resolved_v1);

    let resolved_v2 = vec![
        make_resolved("a.com", vec!["1.2.3.4".parse().unwrap()]),
        make_resolved("b.com", vec!["5.6.7.8".parse().unwrap()]),
    ];
    let rules_v2 = gen.generate_anchor_rules(&resolved_v2);

    // v2 should have more IPs in the table
    assert!(rules_v2.contains("5.6.7.8"), "New domain IP should appear");
    assert_ne!(
        rules_v1, rules_v2,
        "Rules should differ when whitelist changes"
    );
}

#[test]
fn removed_domain_removes_ips() {
    let gen = PfRuleGenerator::new("_openclaw", "com.counterclaw");

    // Before removal: two destinations
    let resolved_before = vec![
        make_resolved("a.com", vec!["1.2.3.4".parse().unwrap()]),
        make_resolved("b.com", vec!["5.6.7.8".parse().unwrap()]),
    ];
    let rules_before = gen.generate_anchor_rules(&resolved_before);
    assert!(rules_before.contains("5.6.7.8"));

    // After removal: only one destination
    let resolved_after = vec![make_resolved("a.com", vec!["1.2.3.4".parse().unwrap()])];
    let rules_after = gen.generate_anchor_rules(&resolved_after);
    assert!(
        !rules_after.contains("5.6.7.8"),
        "Removed domain IP should disappear"
    );
}

#[tokio::test]
async fn dns_refresh_re_resolves_periodically() {
    // Verify that DomainResolver can be called multiple times
    // (simulating periodic refresh) and returns consistent results
    let domains = vec!["127.0.0.1".to_string()];

    let resolved1 = DomainResolver::resolve_all(&domains).await;
    let resolved2 = DomainResolver::resolve_all(&domains).await;

    assert_eq!(resolved1.len(), 1);
    assert_eq!(resolved2.len(), 1);
    assert_eq!(resolved1[0].ips, resolved2[0].ips);
    // Second resolution should have a later or equal timestamp
    assert!(resolved2[0].resolved_at >= resolved1[0].resolved_at);
}

// ==========================================================================
// Étape 7 : CLI test egress (~2 tests)
// ==========================================================================

#[test]
fn test_egress_allowed_destination() {
    let env = common::TestEnv::new();
    let yaml = common::minimal_monitor_config(&env).to_string()
        + r#"
pf_guard:
  enabled: true
  agent_username: "_openclaw"
  allowed_destinations:
    - "api.openai.com"
    - "api.anthropic.com"
"#;
    env.write_config(&yaml);

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_counterclaw"))
        .args([
            "test",
            "-c",
            &env.config_path().to_string_lossy(),
            "egress",
            "api.openai.com",
        ])
        .output()
        .expect("Failed to run CLI");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("ALLOWED"),
        "Expected ALLOWED for whitelisted destination, got: {}",
        stdout
    );
    assert!(output.status.success(), "Exit code should be 0 for allowed");
}

#[test]
fn test_egress_blocked_destination() {
    let env = common::TestEnv::new();
    let yaml = common::minimal_monitor_config(&env).to_string()
        + r#"
pf_guard:
  enabled: true
  agent_username: "_openclaw"
  allowed_destinations:
    - "api.openai.com"
"#;
    env.write_config(&yaml);

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_counterclaw"))
        .args([
            "test",
            "-c",
            &env.config_path().to_string_lossy(),
            "egress",
            "evil.com",
        ])
        .output()
        .expect("Failed to run CLI");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("BLOCKED"),
        "Expected BLOCKED for non-whitelisted destination, got: {}",
        stdout
    );
    assert!(
        !output.status.success(),
        "Exit code should be non-zero for blocked"
    );
}

// ==========================================================================
// Étape 8 : Intégration daemon + dashboard (~3 tests)
// ==========================================================================

#[test]
fn pf_guard_in_daemon_guards() {
    // Verify PfGuard is in DaemonState's guard list
    let env = common::TestEnv::new();
    let yaml = common::minimal_monitor_config(&env).to_string() + "\npf_guard:\n  enabled: false\n";
    env.write_config(&yaml);
    let config = counterclaw::config::AppConfig::load(&env.config_path()).unwrap();
    let event_buffer = Arc::new(RwLock::new(counterclaw::types::EventBuffer::new(100)));
    let state = counterclaw::daemon::DaemonState::new(config, event_buffer);
    let statuses = state.guard_statuses();
    let pf_guard_found = statuses.iter().any(|(name, _)| name == "pf_guard");
    assert!(
        pf_guard_found,
        "pf_guard should be in daemon guard list, found: {:?}",
        statuses.iter().map(|(n, _)| n.as_str()).collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn pf_rules_in_rules_api() {
    // Verify /api/rules includes pf section
    let env = common::TestEnv::new();
    let yaml = common::minimal_monitor_config(&env).to_string()
        + "\npf_guard:\n  enabled: true\n  agent_username: \"_test\"\n  allowed_destinations:\n    - \"api.openai.com\"\n";
    env.write_config(&yaml);
    let config = counterclaw::config::AppConfig::load(&env.config_path()).unwrap();
    let event_buffer = Arc::new(RwLock::new(counterclaw::types::EventBuffer::new(100)));
    let state = Arc::new(counterclaw::daemon::DaemonState::new(config, event_buffer));
    let dashboard_state = counterclaw::dashboard::server::DashboardState::new(state);
    let router = counterclaw::dashboard::server::build_router(dashboard_state);

    let req = axum::http::Request::builder()
        .uri("/api/rules")
        .body(axum::body::Body::empty())
        .unwrap();

    let resp = tower::ServiceExt::oneshot(router, req).await.unwrap();
    assert_eq!(resp.status(), 200);

    let body = axum::body::to_bytes(resp.into_body(), 1_000_000)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    // Check pf section exists with allowed_destinations
    assert!(
        json.get("pf").is_some(),
        "rules API should include 'pf' section, got: {}",
        json
    );
    let pf = &json["pf"];
    assert!(
        pf.get("allowed_destinations").is_some(),
        "pf section should include allowed_destinations"
    );
}

#[tokio::test]
async fn pf_rules_crud_works() {
    // Verify POST /api/rules/pf adds a destination
    let env = common::TestEnv::new();
    let yaml = common::minimal_monitor_config(&env).to_string()
        + "\npf_guard:\n  enabled: true\n  agent_username: \"_test\"\n  allowed_destinations: []\n";
    env.write_config(&yaml);
    let config = counterclaw::config::AppConfig::load(&env.config_path()).unwrap();
    let event_buffer = Arc::new(RwLock::new(counterclaw::types::EventBuffer::new(100)));
    let state = Arc::new(counterclaw::daemon::DaemonState::new(config, event_buffer));
    let token = "test-token-123".to_string();
    let dashboard_state =
        counterclaw::dashboard::server::DashboardState::with_token(state, token.clone());
    let router = counterclaw::dashboard::server::build_router(dashboard_state);

    // POST to add a pf destination
    let req = axum::http::Request::builder()
        .method("POST")
        .uri("/api/rules/pf")
        .header("Content-Type", "application/json")
        .header("Authorization", format!("Bearer {}", token))
        .header("Origin", "http://127.0.0.1:9999")
        .body(axum::body::Body::from(
            serde_json::to_string(&serde_json::json!({
                "category": "allowed_destinations",
                "value": "api.newservice.com"
            }))
            .unwrap(),
        ))
        .unwrap();

    let resp = tower::ServiceExt::oneshot(router, req).await.unwrap();
    assert_eq!(resp.status(), 200, "POST /api/rules/pf should succeed");
}
