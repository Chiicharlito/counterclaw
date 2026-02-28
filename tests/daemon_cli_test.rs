//! Tests for daemon CLI subcommands (start/stop/restart).

use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn daemon_subcommand_appears_in_help() {
    Command::cargo_bin("counterclaw")
        .unwrap()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("daemon").or(predicate::str::contains("Daemon")));
}

#[test]
fn daemon_start_appears_in_help() {
    Command::cargo_bin("counterclaw")
        .unwrap()
        .args(["daemon", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("start").or(predicate::str::contains("Start")));
}

#[test]
fn daemon_stop_prints_message_when_not_loaded() {
    // When plist doesn't exist, daemon stop should fail with a useful message
    Command::cargo_bin("counterclaw")
        .unwrap()
        .args(["daemon", "stop"])
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("not installed")
                .or(predicate::str::contains("not found"))
                .or(predicate::str::contains("Plist")),
        );
}
