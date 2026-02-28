//! Tests for the logs and dashboard CLI commands.

mod common;

use assert_cmd::Command;
use predicates::prelude::*;
use std::io::Write;

#[test]
fn logs_command_appears_in_help() {
    Command::cargo_bin("counterclaw")
        .unwrap()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("logs").or(predicate::str::contains("Logs")));
}

#[test]
fn logs_reads_last_n_events_from_file() {
    // Create a temp log file with 5 JSON lines
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("events.jsonl");
    {
        let mut f = std::fs::File::create(&log_path).unwrap();
        for i in 1..=5 {
            writeln!(
                f,
                r#"{{"timestamp":"2026-01-0{}T00:00:00Z","module":"fs_guard","severity":"warning","description":"event {}"}}"#,
                i, i
            )
            .unwrap();
        }
    }

    // Request last 2 lines
    Command::cargo_bin("counterclaw")
        .unwrap()
        .args(["logs", "--last", "2", "--file", log_path.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("event 4").and(predicate::str::contains("event 5")));
}

#[test]
fn logs_filters_by_severity() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("events.jsonl");
    {
        let mut f = std::fs::File::create(&log_path).unwrap();
        writeln!(
            f,
            r#"{{"timestamp":"2026-01-01T00:00:00Z","module":"fs_guard","severity":"info","description":"info event"}}"#
        )
        .unwrap();
        writeln!(
            f,
            r#"{{"timestamp":"2026-01-02T00:00:00Z","module":"fs_guard","severity":"critical","description":"critical event"}}"#
        )
        .unwrap();
    }

    Command::cargo_bin("counterclaw")
        .unwrap()
        .args([
            "logs",
            "--severity",
            "critical",
            "--file",
            log_path.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("critical event")
                .and(predicate::str::contains("info event").not()),
        );
}

#[test]
fn logs_filters_by_module() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("events.jsonl");
    {
        let mut f = std::fs::File::create(&log_path).unwrap();
        writeln!(
            f,
            r#"{{"timestamp":"2026-01-01T00:00:00Z","module":"fs_guard","severity":"info","description":"fs event"}}"#
        )
        .unwrap();
        writeln!(
            f,
            r#"{{"timestamp":"2026-01-02T00:00:00Z","module":"cdp_proxy","severity":"info","description":"cdp event"}}"#
        )
        .unwrap();
    }

    Command::cargo_bin("counterclaw")
        .unwrap()
        .args([
            "logs",
            "--module",
            "cdp_proxy",
            "--file",
            log_path.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("cdp event").and(predicate::str::contains("fs event").not()),
        );
}

#[test]
fn logs_handles_missing_log_file() {
    Command::cargo_bin("counterclaw")
        .unwrap()
        .args(["logs", "--file", "/tmp/nonexistent_counterclaw_test.jsonl"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("not found").or(predicate::str::contains("No such")));
}

#[test]
fn dashboard_command_appears_in_help() {
    Command::cargo_bin("counterclaw")
        .unwrap()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("dashboard").or(predicate::str::contains("Dashboard")));
}
