//! Tests for BUG 1 — Net Guard: Process Name Mismatch (CRITICAL)
//!
//! lsof truncates COMMAND to ~15 chars. Config expects "openclaw-gateway"
//! but lsof returns "node" (the runtime). These tests verify that
//! process enrichment via sysinfo PID lookup fixes the mismatch.

mod common;

use counterclaw::guards::net_guard::{ConnectionInfo, ConnectionParser};
use counterclaw::process::ProcessScanner;

// ---------------------------------------------------------------------------
// Test 1: ProcessScanner::get_by_pid with nonexistent PID → None
// ---------------------------------------------------------------------------
#[test]
fn process_scanner_get_by_pid_nonexistent() {
    let scanner = ProcessScanner::new();
    // PID 0xFFFFFF is unlikely to exist
    let result = scanner.get_by_pid(0x00FF_FFFF);
    assert!(result.is_none(), "Nonexistent PID should return None");
}

// ---------------------------------------------------------------------------
// Test 2: Truncated lsof name matches via full sysinfo name
// ---------------------------------------------------------------------------
#[test]
fn lsof_truncated_name_matches_via_full_name() {
    // Simulate: lsof reports "node", sysinfo says "openclaw-gateway"
    let patterns = vec!["openclaw-gateway".to_string()];

    // "node" alone does NOT match
    assert!(
        !counterclaw::process::matches_process_patterns("node", "", &patterns),
        "Truncated name 'node' should NOT match 'openclaw-gateway'"
    );

    // But "openclaw-gateway" (full sysinfo name) DOES match
    assert!(
        counterclaw::process::matches_process_patterns("openclaw-gateway", "", &patterns),
        "Full sysinfo name 'openclaw-gateway' should match"
    );

    // ConnectionInfo with enriched full_process_name should match
    let conn = ConnectionInfo {
        pid: 1234,
        process_name: "node".to_string(),
        protocol: "TCP".to_string(),
        target_ip: "93.184.216.34".to_string(),
        target_port: 443,
        full_process_name: Some("openclaw-gateway".to_string()),
        full_cmd: Some("/usr/local/bin/node /opt/openclaw/gateway.js".to_string()),
    };
    assert!(
        conn.matches_watch_processes(&patterns),
        "Enriched ConnectionInfo should match via full_process_name"
    );
}

// ---------------------------------------------------------------------------
// Test 3: Truncated lsof name matches via full cmd regex
// ---------------------------------------------------------------------------
#[test]
fn lsof_truncated_name_matches_via_cmd_regex() {
    let patterns = vec!["node.*openclaw".to_string()];

    let conn = ConnectionInfo {
        pid: 1234,
        process_name: "node".to_string(),
        protocol: "TCP".to_string(),
        target_ip: "93.184.216.34".to_string(),
        target_port: 443,
        full_process_name: Some("node".to_string()),
        full_cmd: Some("/usr/local/bin/node /opt/openclaw/gateway.js".to_string()),
    };

    assert!(
        conn.matches_watch_processes(&patterns),
        "Should match via full_cmd regex: node.*openclaw matches '/usr/local/bin/node /opt/openclaw/gateway.js'"
    );
}

// ---------------------------------------------------------------------------
// Test 4: ConnectionParser preserves PID
// ---------------------------------------------------------------------------
#[test]
fn connection_parser_preserves_pid() {
    let lsof_output = "node      12345  user   10u  IPv4 0x123  0t0  TCP 192.168.1.1:50000->93.184.216.34:443 (ESTABLISHED)";
    let connections = ConnectionParser::parse_lsof_output(lsof_output);
    assert_eq!(connections.len(), 1);
    assert_eq!(connections[0].pid, 12345);
    assert_eq!(connections[0].process_name, "node");
}

// ---------------------------------------------------------------------------
// Test 5: watch_processes empty matches all (regression guard)
// ---------------------------------------------------------------------------
#[test]
fn watch_processes_empty_matches_all() {
    let empty_patterns: Vec<String> = vec![];

    let conn = ConnectionInfo {
        pid: 1234,
        process_name: "anything".to_string(),
        protocol: "TCP".to_string(),
        target_ip: "10.0.0.1".to_string(),
        target_port: 80,
        full_process_name: None,
        full_cmd: None,
    };

    // With empty watch_processes, matches_watch_processes should return true (match all)
    assert!(
        conn.matches_watch_processes(&empty_patterns),
        "Empty watch_processes should match everything"
    );
}
