//! Tests for BUG 7 — FS Guard: opensnoop read detection (LOW)
//!
//! notify crate (FSEvents macOS) doesn't report file reads.
//! OpensnoopParser parses `opensnoop` output to detect them.

mod common;

use counterclaw::config::FsGuardConfig;
use counterclaw::guards::fs_guard::{OpensnoopEvent, OpensnoopParser};

// ---------------------------------------------------------------------------
// Test 1: Parser extracts PID and path from typical opensnoop output
// ---------------------------------------------------------------------------
#[test]
fn parser_extracts_pid_and_path() {
    // Typical opensnoop output line: "  PID    COMM      FD PATH"
    // then data lines like:         "12345    node       3 /Users/test/.ssh/config"
    let line = "12345    node       3 /Users/test/.ssh/config";
    let event = OpensnoopParser::parse_line(line);
    assert!(event.is_some(), "Should parse a valid opensnoop line");
    let ev = event.unwrap();
    assert_eq!(ev.pid, 12345);
    assert_eq!(ev.process_name, "node");
    assert_eq!(ev.fd, 3);
    assert_eq!(ev.path, "/Users/test/.ssh/config");
}

// ---------------------------------------------------------------------------
// Test 2: Parser ignores header line
// ---------------------------------------------------------------------------
#[test]
fn parser_ignores_headers() {
    let line = "  PID    COMM      FD PATH";
    let event = OpensnoopParser::parse_line(line);
    assert!(event.is_none(), "Header line should return None");
}

// ---------------------------------------------------------------------------
// Test 3: Parser handles empty input
// ---------------------------------------------------------------------------
#[test]
fn parser_handles_empty_input() {
    let event = OpensnoopParser::parse_line("");
    assert!(event.is_none(), "Empty line should return None");

    let event2 = OpensnoopParser::parse_line("   ");
    assert!(event2.is_none(), "Whitespace-only line should return None");
}

// ---------------------------------------------------------------------------
// Test 4: Parser handles paths with spaces
// ---------------------------------------------------------------------------
#[test]
fn parser_handles_paths_with_spaces() {
    let line = "  456    safari     5 /Users/test/My Documents/secrets.txt";
    let event = OpensnoopParser::parse_line(line);
    assert!(event.is_some(), "Should handle paths with spaces");
    let ev = event.unwrap();
    assert_eq!(ev.pid, 456);
    assert_eq!(ev.process_name, "safari");
    assert_eq!(ev.path, "/Users/test/My Documents/secrets.txt");
}

// ---------------------------------------------------------------------------
// Test 5: monitor_reads config default is false
// ---------------------------------------------------------------------------
#[test]
fn monitor_reads_config_default_false() {
    let yaml = r#"
enabled: true
watch_processes: []
blocked_paths: []
read_only_paths: []
allowed_paths: []
on_violation:
  action: log_only
  kill_target: process
"#;
    let config: FsGuardConfig = serde_yaml::from_str(yaml).unwrap();
    assert!(
        !config.monitor_reads,
        "Default monitor_reads should be false"
    );
}
