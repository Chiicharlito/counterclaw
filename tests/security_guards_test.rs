//! Security tests for guard hardening (daemon, engine, macos_notify, cmd_guard, net_guard)

mod common;

use counterclaw::config::CmdGuardConfig;

// === Step 2.6 — PID file exclusive creation ===

#[test]
fn pid_file_exclusive_creation() {
    let env = common::TestEnv::new();
    let pid_path = env.root().join("test.pid");

    // First creation should succeed
    counterclaw::daemon::write_pid_file(&pid_path, std::process::id()).unwrap();
    assert!(pid_path.exists());

    // Content should be current PID
    let content = std::fs::read_to_string(&pid_path).unwrap();
    assert_eq!(content.trim(), std::process::id().to_string());

    // Cleanup
    std::fs::remove_file(&pid_path).unwrap();
}

#[test]
fn pid_file_rejects_symlink() {
    let env = common::TestEnv::new();
    let real_path = env.root().join("real.pid");
    let link_path = env.root().join("link.pid");

    // Create a symlink
    std::fs::write(&real_path, "12345").unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(&real_path, &link_path).unwrap();

    #[cfg(unix)]
    {
        let result = counterclaw::daemon::write_pid_file(&link_path, std::process::id());
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("symlink"));
    }
}

#[test]
fn pid_file_removes_stale_and_recreates() {
    let env = common::TestEnv::new();
    let pid_path = env.root().join("test_stale.pid");

    // Write a stale PID (99999999 — very unlikely to be running)
    std::fs::write(&pid_path, "99999999").unwrap();

    // Should succeed because the stale PID is not running
    counterclaw::daemon::write_pid_file(&pid_path, std::process::id()).unwrap();

    let content = std::fs::read_to_string(&pid_path).unwrap();
    assert_eq!(content.trim(), std::process::id().to_string());
}

// === Step 1.4 — macOS notify sanitization ===

#[test]
fn sanitizes_backtick_injection() {
    let result = counterclaw::alerting::macos_notify::sanitize("test `whoami` injection");
    // The backtick should be escaped as \`
    assert!(result.contains("\\`"));
    // No raw unescaped backtick (every backtick should be preceded by backslash)
    assert_eq!(
        result, r"test \`whoami\` injection",
        "Backticks should be escaped"
    );
}

#[test]
fn sanitizes_dollar_command_substitution() {
    let result = counterclaw::alerting::macos_notify::sanitize("test $(cat /etc/passwd) attack");
    assert!(result.contains("\\$"));
}

#[test]
fn sanitizes_newline_injection() {
    let result = counterclaw::alerting::macos_notify::sanitize("line1\nline2\rline3");
    assert!(!result.contains('\n'));
    assert!(!result.contains('\r'));
}

#[test]
fn truncates_oversized_messages() {
    let long_msg = "A".repeat(500);
    let result = counterclaw::alerting::macos_notify::sanitize(&long_msg);
    assert!(result.len() <= 256);
}

#[test]
fn sanitizes_curly_braces() {
    let result = counterclaw::alerting::macos_notify::sanitize("test {expansion} here");
    // Curly braces should be escaped as \{ and \}
    assert!(result.contains("\\{"));
    assert!(result.contains("\\}"));
    assert_eq!(
        result, r"test \{expansion\} here",
        "Curly braces should be escaped"
    );
}

// === Step 2.3 — Cmd Guard shell encoding detection ===

fn empty_cmd_config() -> CmdGuardConfig {
    CmdGuardConfig {
        enabled: false,
        blacklist: vec![],
        require_approval: vec![],
        monitoring_method: "log_only".to_string(),
        poll_interval_ms: 500,
    }
}

#[test]
fn detects_command_substitution_evasion() {
    let matcher = counterclaw::guards::cmd_guard::CommandMatcher::new(&empty_cmd_config());
    assert!(matcher.check_evasion("echo $(cat /etc/passwd)").is_some());
}

#[test]
fn detects_backtick_evasion() {
    let matcher = counterclaw::guards::cmd_guard::CommandMatcher::new(&empty_cmd_config());
    assert!(matcher.check_evasion("echo `whoami`").is_some());
}

#[test]
fn detects_hex_encoded_command() {
    let matcher = counterclaw::guards::cmd_guard::CommandMatcher::new(&empty_cmd_config());
    assert!(matcher.check_evasion(r"echo \x63\x61\x74").is_some());
}

#[test]
fn detects_eval_evasion() {
    let matcher = counterclaw::guards::cmd_guard::CommandMatcher::new(&empty_cmd_config());
    assert!(matcher.check_evasion("eval 'rm -rf /'").is_some());
}

#[test]
fn detects_base64_decode_evasion() {
    let matcher = counterclaw::guards::cmd_guard::CommandMatcher::new(&empty_cmd_config());
    assert!(matcher
        .check_evasion("echo dGVzdA== | base64 --decode")
        .is_some());
    assert!(matcher.check_evasion("echo dGVzdA== | base64 -d").is_some());
}

#[test]
fn allows_normal_commands_without_evasion() {
    let matcher = counterclaw::guards::cmd_guard::CommandMatcher::new(&empty_cmd_config());
    assert!(matcher.check_evasion("ls -la /tmp").is_none());
    assert!(matcher.check_evasion("git status").is_none());
    assert!(matcher.check_evasion("cargo build --release").is_none());
}

// === Step 2.4 — DNS rebinding detection ===

#[test]
fn dns_cache_detects_ip_change() {
    let mut cache = counterclaw::guards::net_guard::DnsCache::new();

    // First resolution - OK
    assert!(cache.record("example.com", "1.2.3.4").is_none());

    // Same IP - OK
    assert!(cache.record("example.com", "1.2.3.4").is_none());

    // Different IP - rebinding detected
    let old = cache.record("example.com", "10.0.0.1");
    assert_eq!(old, Some("1.2.3.4".to_string()));
}

#[test]
fn dns_cache_case_insensitive() {
    let mut cache = counterclaw::guards::net_guard::DnsCache::new();
    assert!(cache.record("Example.COM", "1.2.3.4").is_none());
    assert!(cache.record("example.com", "1.2.3.4").is_none()); // Same domain, same IP
}

#[test]
fn dns_cache_tracks_multiple_domains() {
    let mut cache = counterclaw::guards::net_guard::DnsCache::new();
    assert!(cache.record("a.com", "1.1.1.1").is_none());
    assert!(cache.record("b.com", "2.2.2.2").is_none());
    // a.com changes
    let old = cache.record("a.com", "3.3.3.3");
    assert_eq!(old, Some("1.1.1.1".to_string()));
    // b.com stays the same
    assert!(cache.record("b.com", "2.2.2.2").is_none());
}

// === Step 3.5 — Raw IP detection ===

#[test]
fn detects_raw_ipv4_address() {
    assert!(counterclaw::guards::net_guard::EgressMatcher::is_raw_ip(
        "192.168.1.1"
    ));
    assert!(counterclaw::guards::net_guard::EgressMatcher::is_raw_ip(
        "10.0.0.1"
    ));
}

#[test]
fn detects_raw_ipv6_address() {
    assert!(counterclaw::guards::net_guard::EgressMatcher::is_raw_ip(
        "::1"
    ));
    assert!(counterclaw::guards::net_guard::EgressMatcher::is_raw_ip(
        "fe80::1"
    ));
}

#[test]
fn domain_name_is_not_raw_ip() {
    assert!(!counterclaw::guards::net_guard::EgressMatcher::is_raw_ip(
        "github.com"
    ));
    assert!(!counterclaw::guards::net_guard::EgressMatcher::is_raw_ip(
        "api.example.com"
    ));
}

#[test]
fn empty_string_is_not_raw_ip() {
    assert!(!counterclaw::guards::net_guard::EgressMatcher::is_raw_ip(
        ""
    ));
}

// === Step 2.7 — Event buffer priority ===

#[test]
fn buffer_preserves_critical_events_during_flood() {
    use counterclaw::types::{ActionTaken, EventBuffer, GuardModule, SecurityEvent, Severity};

    // Create a small buffer (capacity 5)
    let mut buffer = EventBuffer::new(5);

    // Add 3 critical events
    for i in 0..3 {
        buffer.push(SecurityEvent::new(
            GuardModule::System,
            Severity::Critical,
            ActionTaken::Logged,
            format!("Critical event {}", i),
        ));
    }

    // Flood with 10 info events
    for i in 0..10 {
        buffer.push(SecurityEvent::new(
            GuardModule::System,
            Severity::Info,
            ActionTaken::Logged,
            format!("Info flood {}", i),
        ));
    }

    // All critical events should still be in buffer
    let events = buffer.query(0, None, None, None);
    let critical_count = events
        .iter()
        .filter(|e| e.severity == Severity::Critical)
        .count();
    assert!(
        critical_count >= 3,
        "Critical events should be preserved during info flood, got {}",
        critical_count
    );
}

#[test]
fn buffer_evicts_low_priority_when_high_arrives() {
    use counterclaw::types::{ActionTaken, EventBuffer, GuardModule, SecurityEvent, Severity};

    // Create a buffer of capacity 3
    let mut buffer = EventBuffer::new(3);

    // Fill with info events
    for i in 0..3 {
        buffer.push(SecurityEvent::new(
            GuardModule::System,
            Severity::Info,
            ActionTaken::Logged,
            format!("Info {}", i),
        ));
    }
    assert_eq!(buffer.len(), 3);

    // Add a high-severity event — should evict an info event, not drop
    buffer.push(SecurityEvent::new(
        GuardModule::System,
        Severity::High,
        ActionTaken::Blocked,
        "High priority event".to_string(),
    ));
    assert_eq!(buffer.len(), 3);

    let events = buffer.query(0, None, None, None);
    let high_count = events
        .iter()
        .filter(|e| e.severity == Severity::High)
        .count();
    assert_eq!(high_count, 1, "High event should be preserved");
}

#[test]
fn buffer_normal_eviction_for_low_priority() {
    use counterclaw::types::{ActionTaken, EventBuffer, GuardModule, SecurityEvent, Severity};

    // Create a buffer of capacity 2
    let mut buffer = EventBuffer::new(2);

    buffer.push(SecurityEvent::new(
        GuardModule::System,
        Severity::Info,
        ActionTaken::Logged,
        "First".to_string(),
    ));
    buffer.push(SecurityEvent::new(
        GuardModule::System,
        Severity::Info,
        ActionTaken::Logged,
        "Second".to_string(),
    ));
    // Adding a third info event should evict the oldest (First)
    buffer.push(SecurityEvent::new(
        GuardModule::System,
        Severity::Info,
        ActionTaken::Logged,
        "Third".to_string(),
    ));

    assert_eq!(buffer.len(), 2);
    let events = buffer.query(0, None, None, None);
    // Should have Second and Third (most recent first due to rev())
    assert!(events.iter().any(|e| e.description == "Third"));
    assert!(events.iter().any(|e| e.description == "Second"));
}
