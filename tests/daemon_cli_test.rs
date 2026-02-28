//! Tests for daemon CLI subcommands (start/stop/restart).

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

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
    // Override HOME so plist_install_path resolves to a temp dir where no plist exists.
    // This isolates the test from the real ~/Library/LaunchAgents/.
    let fake_home = TempDir::new().expect("Failed to create temp dir");

    Command::cargo_bin("counterclaw")
        .unwrap()
        .args(["daemon", "stop"])
        .env("HOME", fake_home.path())
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("not installed")
                .or(predicate::str::contains("not found"))
                .or(predicate::str::contains("Plist")),
        );
}
